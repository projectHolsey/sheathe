/*
 * net_monitor.h — Public API for the TCP network monitor module.
 *
 * Include this header in any C file that wants to use the monitor.
 * The implementation lives in net_monitor.c; link both together at
 * compile time (see the README at the bottom of net_monitor.c).
 *
 * Usage pattern
 * ─────────────
 *   #include "net_monitor.h"
 *
 *   NetMonitorConfig cfg = {
 *       .bind_ip   = "0.0.0.0",   // listen on all interfaces
 *       .port      = 8080,
 *       .max_conns = 10,
 *       .on_packet = my_callback,  // called once per received payload
 *   };
 *   net_monitor_run(&cfg);         // blocks; Ctrl-C to stop
 */

#ifndef NET_MONITOR_H
#define NET_MONITOR_H

#include <stddef.h>   /* size_t                         */
#include <stdint.h>   /* uint16_t, uint32_t, …          */
#include <time.h>     /* struct timespec (wall-clock ts) */

/* ── Captured TCP connection metadata ─────────────────────────────────────
 *
 * Everything here can be fed back into a raw-socket replay tool later:
 *   • src/dst IP + port  → reconstruct the 5-tuple
 *   • seq / ack numbers  → resume a TCP stream at the right byte offset
 *   • window size        → honour the original flow-control values
 *   • flags              → distinguish SYN / FIN / RST / PSH / ACK
 *   • timestamp          → replay with correct inter-packet timing
 */
typedef struct {
    /* --- addressing ---------------------------------------------------- */
    char     src_ip[46];   /* source IP (IPv4 dotted-decimal or IPv6 text) */
    char     dst_ip[46];   /* destination IP                               */
    uint16_t src_port;     /* source (ephemeral) port                      */
    uint16_t dst_port;     /* destination (listening) port                 */

    /* --- TCP header fields ---------------------------------------------- */
    uint32_t seq;          /* sequence number from the TCP header           */
    uint32_t ack;          /* acknowledgement number                        */
    uint16_t window;       /* advertised receive window (bytes)             */
    uint8_t  flags;        /* TCP control bits: FIN SYN RST PSH ACK URG    */
    uint8_t  data_offset;  /* header length in 32-bit words (4–15)         */

    /* --- payload -------------------------------------------------------- */
    const unsigned char *payload; /* pointer into the receive buffer        */
    size_t               payload_len;

    /* --- timing --------------------------------------------------------- */
    struct timespec arrived_at; /* wall-clock time; use clock_gettime()     */
} NetPacket;

/* ── Callback signature ────────────────────────────────────────────────────
 *
 * Your code receives a const pointer to a NetPacket.  The packet is only
 * valid inside the callback; copy anything you need to keep.
 */
typedef void (*net_monitor_cb)(const NetPacket *pkt, void *user_data);

/* ── Monitor configuration ─────────────────────────────────────────────── */
typedef struct {
    const char      *bind_ip;    /* IP to listen on, e.g. "0.0.0.0" or "127.0.0.1" */
    uint16_t         port;       /* TCP port to bind                                 */
    int              max_conns;  /* accept() backlog / simultaneous connections      */
    net_monitor_cb   on_packet;  /* called for every received segment                */
    void            *user_data;  /* passed through unchanged to on_packet            */
} NetMonitorConfig;

/* ── Public functions ──────────────────────────────────────────────────── */

/*
 * net_monitor_run()
 *   Binds, listens, and enters an accept-loop.  For each client it reads
 *   raw bytes, reconstructs TCP metadata via getsockopt(TCP_INFO) and the
 *   peer address, then calls cfg->on_packet().
 *
 *   Blocks until SIGINT/SIGTERM or a fatal error.
 *   Returns 0 on clean shutdown, -1 on error (errno set).
 */
int net_monitor_run(const NetMonitorConfig *cfg);

/*
 * net_packet_flags_str()
 *   Fills `buf` (must be ≥ 9 bytes) with a human-readable flag string
 *   e.g. "..RPAFS" (URG ACK PSH RST SYN FIN order, '.' = not set).
 */
void net_packet_flags_str(uint8_t flags, char *buf, size_t buf_len);

/*
 * net_packet_print()
 *   Convenience function: pretty-prints a NetPacket to stdout.
 *   This is what net_monitor_run() uses internally as a default when
 *   on_packet is NULL — and it's what you call from your own callback
 *   if you just want the standard dump.
 */
void net_packet_print(const NetPacket *pkt);

#endif /* NET_MONITOR_H */
