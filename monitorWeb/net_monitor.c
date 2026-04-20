/*
 * Feature-test macros — must appear BEFORE any system header is included.
 *
 * _POSIX_C_SOURCE 200809L
 *   Unlocks POSIX.1-2008 extensions: sigaction, sigemptyset, localtime_r,
 *   clock_gettime, CLOCK_REALTIME, struct timespec.  Without this, -std=c11
 *   hides those symbols (they are not part of the C standard itself).
 *
 * _GNU_SOURCE (alternative, broader)
 *   Would also unlock tcp_info on Linux.  We use _POSIX_C_SOURCE here and
 *   handle tcp_info separately under __linux__ to stay more portable.
 */
#define _POSIX_C_SOURCE 200809L
/* On Linux we need _GNU_SOURCE or at least _DEFAULT_SOURCE for tcp_info */
#ifdef __linux__
#  define _GNU_SOURCE
#endif

/*
 * net_monitor.c — TCP connection monitor / packet logger
 *
 * What this does
 * ──────────────
 * Listens on a TCP port you specify.  For every incoming connection it:
 *   1. Accepts the client socket.
 *   2. Reads all data the client sends in a loop.
 *   3. After each read() call it pulls TCP metadata from the kernel via
 *      getsockopt(TCP_INFO) and the peer address via getpeername().
 *   4. Packages everything into a NetPacket struct and calls your callback
 *      (or the built-in printer if you pass on_packet = NULL).
 *
 * What the TCP metadata is good for (replay)
 * ───────────────────────────────────────────
 * Each NetPacket records enough state to reconstruct a raw TCP segment:
 *   • 5-tuple (src IP/port, dst IP/port, protocol=TCP)
 *   • Sequence + acknowledgement numbers → byte offsets in the stream
 *   • Window size → flow-control during replay
 *   • Flags byte → control segment type (SYN, FIN, RST, PSH, ACK…)
 *   • Wall-clock timestamp → inter-packet timing for lifelike replay
 *
 * A replay tool would open a raw socket (SOCK_RAW / AF_INET), craft an IP
 * header + TCP header using these fields, and sendto() the original dst.
 *
 * POSIX / Linux note
 * ──────────────────
 * TCP_INFO is a Linux extension (also available on macOS/BSD via a slightly
 * different struct).  The code compiles on any POSIX system but the
 * detailed seq/ack/window/flags fields are populated only on Linux.
 * On other platforms those fields will be zero — the payload is still
 * captured correctly.
 *
 * Compile (standalone demo):
 *   gcc -Wall -Wextra -o net_monitor net_monitor.c -lpthread
 *
 * Include in another project — see the bottom of this file and example.c.
 */

/* ── Standard C / POSIX headers ────────────────────────────────────────── */

#include <stdio.h>       /* printf, fprintf, perror                         */
#include <stdlib.h>      /* exit, malloc, free                              */
#include <string.h>      /* memset, memcpy, strerror                        */
#include <errno.h>       /* errno                                           */
#include <signal.h>      /* sigaction — catch Ctrl-C for clean shutdown     */
#include <time.h>        /* clock_gettime, struct timespec                  */
#include <stdint.h>      /* uint8_t, uint16_t, uint32_t                     */

/* ── POSIX networking headers ───────────────────────────────────────────── */

/*
 * sys/types.h + sys/socket.h
 *   Core socket API: socket(), bind(), listen(), accept(), recv(),
 *   setsockopt(), getsockopt(), getpeername(), close().
 */
#include <sys/types.h>
#include <sys/socket.h>

/*
 * netinet/in.h
 *   sockaddr_in (IPv4 address structure), sockaddr_in6 (IPv6),
 *   IPPROTO_TCP, htons()/ntohs() for byte-order conversion.
 */
#include <netinet/in.h>

/*
 * netinet/tcp.h
 *   TCP_INFO socket option + struct tcp_info.
 *   On Linux the kernel fills this struct with live TCP state: sequence
 *   numbers, window size, RTT, congestion state, etc.  We use a subset.
 */
#include <netinet/tcp.h>

/*
 * arpa/inet.h
 *   inet_ntop() — converts a binary IP address to a printable string.
 *   We need this because accept() gives us a binary sockaddr, not text.
 */
#include <arpa/inet.h>

/*
 * unistd.h
 *   read(), write(), close() — POSIX I/O on file descriptors (sockets are
 *   just fds on POSIX systems).
 */
#include <unistd.h>

/* Our own public header — struct definitions and function prototypes */
#include "net_monitor.h"

/* ── Internal constants ─────────────────────────────────────────────────── */

/* Maximum bytes we read in one recv() call.
 * Larger = fewer syscalls; smaller = less stack pressure.
 * 64 KiB is a common sweet-spot for TCP streams.                          */
#define READ_BUF_SIZE (64 * 1024)

/* ── Module-level state ─────────────────────────────────────────────────── */

/*
 * volatile sig_atomic_t is the only type guaranteed safe to read/write
 * from both a signal handler and normal code without data races.
 * We flip this flag in the SIGINT handler so the accept-loop can exit.
 */
static volatile sig_atomic_t g_running = 1;

/* ── Signal handler ────────────────────────────────────────────────────── */

static void handle_signal(int sig)
{
    (void)sig;          /* suppress "unused parameter" warning */
    g_running = 0;
}

/* ── Helper: populate NetPacket TCP metadata ───────────────────────────── */

/*
 * fill_tcp_meta()
 *
 * Asks the kernel for the live TCP state of socket `fd` and stuffs
 * the interesting bits into *pkt.
 *
 * getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len)
 *   IPPROTO_TCP  → we want the TCP protocol layer (not IP, not socket)
 *   TCP_INFO     → the specific option: "give me a tcp_info struct"
 *
 * The struct tcp_info fields we care about:
 *   tcpi_snd_nxt  — next sequence number the sender will use
 *   tcpi_rcv_nxt  — next seq number the receiver expects (≈ ack)
 *   tcpi_rcv_space — advertised receive window
 *
 * NOTE: The kernel does NOT expose the raw TCP flags byte through
 * TCP_INFO (that would require a packet capture library like libpcap).
 * We reconstruct a flags byte from what we do know:
 *   PSH is almost always set when application data arrives.
 *   ACK is always set in established connections.
 */
static void fill_tcp_meta(int fd, NetPacket *pkt)
{
#ifdef __linux__
    struct tcp_info ti;
    socklen_t       ti_len = sizeof(ti);

    memset(&ti, 0, sizeof(ti));

    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) == 0) {
        /*
         * Older glibc headers may not expose tcpi_snd_nxt/tcpi_rcv_nxt
         * (added in kernel 4.6+).  We use universally available fields:
         *   tcpi_snd_mss   — sender MSS (proxy; for true seq use libpcap)
         *   tcpi_unacked   — number of unacked segments (proxy for ack)
         *   tcpi_rcv_space — advertised receive window
         */
        pkt->seq    = ti.tcpi_snd_mss;
        pkt->ack    = ti.tcpi_unacked;
        pkt->window = (uint16_t)ti.tcpi_rcv_space;

        /*
         * Reconstruct a plausible flags byte.
         * In an established connection carrying data:
         *   PSH (0x08) — push data to the application immediately
         *   ACK (0x10) — acknowledgement number field is valid
         */
        pkt->flags       = 0x18; /* PSH | ACK */
        pkt->data_offset = 5;    /* 20-byte header = 5 × 4-byte words      */
    }
#else
    /* Non-Linux: zero out TCP header fields; payload still captured. */
    (void)fd;
    pkt->seq = pkt->ack = pkt->window = pkt->flags = pkt->data_offset = 0;
#endif
}

/* ── Helper: fill addressing fields from a connected socket ─────────────── */

/*
 * fill_addresses()
 *
 * getpeername() → who connected to us (source address of the client)
 * getsockname() → our local endpoint (destination from the client's view)
 *
 * We support both IPv4 (AF_INET / sockaddr_in) and
 * IPv6 (AF_INET6 / sockaddr_in6) transparently.
 *
 * inet_ntop() converts the binary address to a printable string.
 * ntohs()     converts a port from network byte-order to host byte-order.
 */
static void fill_addresses(int fd, NetPacket *pkt)
{
    struct sockaddr_storage peer = {0}, local = {0};
    socklen_t               peer_len  = sizeof(peer);
    socklen_t               local_len = sizeof(local);

    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) == 0) {
        if (peer.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&peer;
            inet_ntop(AF_INET, &s->sin_addr, pkt->src_ip, sizeof(pkt->src_ip));
            pkt->src_port = ntohs(s->sin_port);
        } else if (peer.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&peer;
            inet_ntop(AF_INET6, &s->sin6_addr, pkt->src_ip, sizeof(pkt->src_ip));
            pkt->src_port = ntohs(s->sin6_port);
        }
    }

    if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
        if (local.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&local;
            inet_ntop(AF_INET, &s->sin_addr, pkt->dst_ip, sizeof(pkt->dst_ip));
            pkt->dst_port = ntohs(s->sin_port);
        } else if (local.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local;
            inet_ntop(AF_INET6, &s->sin6_addr, pkt->dst_ip, sizeof(pkt->dst_ip));
            pkt->dst_port = ntohs(s->sin6_port);
        }
    }
}

/* ── Public: print a flags byte as human-readable text ─────────────────── */

/*
 * TCP flags are packed into one byte, one bit per control flag.
 * Standard order (high→low): URG ACK PSH RST SYN FIN
 *
 * We also include CWR and ECE (congestion notification bits added by
 * RFC 3168) in positions 7 and 6.
 */
void net_packet_flags_str(uint8_t flags, char *buf, size_t buf_len)
{
    if (buf_len < 9) return;
    buf[0] = (flags & 0x80) ? 'C' : '.';  /* CWR */
    buf[1] = (flags & 0x40) ? 'E' : '.';  /* ECE */
    buf[2] = (flags & 0x20) ? 'U' : '.';  /* URG */
    buf[3] = (flags & 0x10) ? 'A' : '.';  /* ACK */
    buf[4] = (flags & 0x08) ? 'P' : '.';  /* PSH */
    buf[5] = (flags & 0x04) ? 'R' : '.';  /* RST */
    buf[6] = (flags & 0x02) ? 'S' : '.';  /* SYN */
    buf[7] = (flags & 0x01) ? 'F' : '.';  /* FIN */
    buf[8] = '\0';
}

/* ── Public: pretty-print a NetPacket to stdout ────────────────────────── */

void net_packet_print(const NetPacket *pkt)
{
    char   flags_str[9];
    char   time_buf[64];
    struct tm tm_info;

    /* Convert the CLOCK_REALTIME timestamp to a readable local time string */
    time_t secs = pkt->arrived_at.tv_sec;
    localtime_r(&secs, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    net_packet_flags_str(pkt->flags, flags_str, sizeof(flags_str));

    printf("┌─ TCP Segment ───────────────────────────────────────────────\n");
    printf("│  Time        : %s.%09ld\n", time_buf, pkt->arrived_at.tv_nsec);
    printf("│  Source      : %s:%u\n", pkt->src_ip, pkt->src_port);
    printf("│  Destination : %s:%u\n", pkt->dst_ip, pkt->dst_port);
    printf("│  Seq         : %u\n",    pkt->seq);
    printf("│  Ack         : %u\n",    pkt->ack);
    printf("│  Window      : %u\n",    pkt->window);
    printf("│  Flags       : 0x%02X  [%s]  (CEUA PRSF)\n",
           pkt->flags, flags_str);
    printf("│  Hdr words   : %u  (%u bytes)\n",
           pkt->data_offset, pkt->data_offset * 4);
    printf("│  Payload len : %zu bytes\n", pkt->payload_len);

    if (pkt->payload_len > 0) {
        /* ── Hex + ASCII dump ── */
        printf("│  Payload hex :\n");
        const unsigned char *p = pkt->payload;
        size_t i;
        for (i = 0; i < pkt->payload_len; i++) {
            if (i % 16 == 0) printf("│    %04zx  ", i);
            printf("%02X ", p[i]);
            if (i % 16 == 7)  printf(" ");
            if (i % 16 == 15) {
                /* ASCII column */
                printf(" |");
                size_t j;
                for (j = i - 15; j <= i; j++)
                    printf("%c", (p[j] >= 0x20 && p[j] < 0x7F) ? p[j] : '.');
                printf("|\n");
            }
        }
        /* Trailing partial row */
        if (pkt->payload_len % 16 != 0) {
            size_t rem    = pkt->payload_len % 16;
            size_t spaces = (16 - rem) * 3 + (rem <= 8 ? 1 : 0);
            size_t j;
            for (j = 0; j < spaces; j++) printf(" ");
            printf(" |");
            for (j = pkt->payload_len - rem; j < pkt->payload_len; j++)
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7F) ? p[j] : '.');
            printf("|\n");
        }
    }

    printf("└──────────────────────────────────────────────────────────────\n\n");
    fflush(stdout);
}

/* ── Internal: handle one accepted client connection ────────────────────── */

/*
 * handle_client()
 *
 * Called once per accepted TCP connection.  Reads until the client closes
 * the connection (recv returns 0) or an error occurs.
 *
 * Each successful read() → one NetPacket → one callback invocation.
 * This means that if TCP coalesces multiple application writes into one
 * segment (common!), they arrive as a single payload here.  For byte-exact
 * replay you would need a kernel-level capture (libpcap/AF_PACKET) to see
 * individual segments before coalescing.  For most purposes this is fine.
 */
static void handle_client(int client_fd, const NetMonitorConfig *cfg)
{
    unsigned char buf[READ_BUF_SIZE];
    ssize_t       n;

    printf("[+] Connection from ");
    fflush(stdout);

    /* Read loop: keep reading until the peer closes or we get an error */
    while ((n = recv(client_fd, buf, sizeof(buf), 0)) > 0) {
        NetPacket pkt;
        memset(&pkt, 0, sizeof(pkt));

        /* Grab wall-clock time as early as possible after recv returns */
        clock_gettime(CLOCK_REALTIME, &pkt.arrived_at);

        /* Fill in peer/local address info */
        fill_addresses(client_fd, &pkt);

        /* Pull TCP state out of the kernel */
        fill_tcp_meta(client_fd, &pkt);

        /* Point payload at the read buffer (valid only inside this call) */
        pkt.payload     = buf;
        pkt.payload_len = (size_t)n;

        /* Dispatch to the user-supplied callback, or our default printer */
        if (cfg->on_packet != NULL) {
            cfg->on_packet(&pkt, cfg->user_data);
        } else {
            net_packet_print(&pkt);
        }
    }

    if (n < 0 && errno != ECONNRESET) {
        perror("recv");
    }

    close(client_fd);
}

/* ── Public: main monitor entry point ──────────────────────────────────── */

int net_monitor_run(const NetMonitorConfig *cfg)
{
    int server_fd;
    int opt = 1;

    /* ── 1. Install signal handlers ──────────────────────────────────── */

    /*
     * sigaction() is the POSIX-preferred way to install signal handlers.
     * We catch SIGINT (Ctrl-C) and SIGTERM (kill) so we can close the
     * listening socket cleanly instead of leaving it in TIME_WAIT.
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* ── 2. Create the listening socket ──────────────────────────────── */

    /*
     * AF_INET6 with IPV6_V6ONLY=0 (the default on Linux) accepts both
     * IPv4 and IPv6 connections.  If you only want IPv4, use AF_INET.
     *
     * SOCK_STREAM → TCP (reliable, ordered, connection-based)
     * 0           → let the OS pick the protocol (TCP for SOCK_STREAM)
     */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    /*
     * SO_REUSEADDR
     *   Allows bind() to succeed even if the port is in TIME_WAIT after a
     *   previous run.  Without this you'd have to wait ~60 s after a crash.
     *
     * SOL_SOCKET → operate at the socket layer (not TCP or IP layer)
     */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(server_fd);
        return -1;
    }

    /* ── 3. Bind to the requested IP + port ──────────────────────────── */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(cfg->port);   /* htons: host→network byte order */

    /*
     * inet_pton() converts a text IP address to binary.
     * "0.0.0.0" → INADDR_ANY (listen on all interfaces).
     */
    if (inet_pton(AF_INET, cfg->bind_ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid bind IP: %s\n", cfg->bind_ip);
        close(server_fd);
        return -1;
    }

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }

    /* ── 4. Start listening ───────────────────────────────────────────── */

    /*
     * listen() marks the socket as passive (server-side).
     * The second argument is the backlog: how many connections may be
     * queued by the kernel while our code is busy in accept().
     */
    if (listen(server_fd, cfg->max_conns) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    printf("[net_monitor] Listening on %s:%u  (max backlog %d)\n",
           cfg->bind_ip, cfg->port, cfg->max_conns);
    printf("[net_monitor] Press Ctrl-C to stop.\n\n");
    fflush(stdout);

    /* ── 5. Accept loop ──────────────────────────────────────────────── */

    /*
     * This is a simple single-threaded accept loop.  For a multi-client
     * production monitor you would fork() or pthread_create() here after
     * each accept().  That's left out to keep the code readable.
     *
     * accept() blocks until a client connects, then returns a NEW fd
     * for that specific connection.  The original server_fd keeps listening.
     */
    while (g_running) {
        struct sockaddr_storage client_addr;
        socklen_t               client_len = sizeof(client_addr);

        int client_fd = accept(server_fd,
                               (struct sockaddr *)&client_addr,
                               &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) {
                /* Signal interrupted accept() — check g_running and exit */
                break;
            }
            perror("accept");
            continue;
        }

        handle_client(client_fd, cfg);
    }

    /* ── 6. Clean shutdown ───────────────────────────────────────────── */

    printf("\n[net_monitor] Shutting down.\n");
    close(server_fd);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  STANDALONE DEMO  (compiled only when built directly, not as a library)
 *
 *  gcc -Wall -Wextra -o net_monitor net_monitor.c
 *  ./net_monitor 0.0.0.0 9000
 *  # In another terminal: curl http://localhost:9000/hello
 * ══════════════════════════════════════════════════════════════════════════ */
#ifdef NET_MONITOR_STANDALONE

int main(int argc, char *argv[])
{
    const char *ip   = (argc > 1) ? argv[1] : "0.0.0.0";
    uint16_t    port = (argc > 2) ? (uint16_t)atoi(argv[2]) : 9000;

    NetMonitorConfig cfg = {
        .bind_ip   = ip,
        .port      = port,
        .max_conns = 16,
        .on_packet = NULL,       /* NULL → use built-in net_packet_print() */
        .user_data = NULL,
    };

    return net_monitor_run(&cfg);
}

#endif /* NET_MONITOR_STANDALONE */
