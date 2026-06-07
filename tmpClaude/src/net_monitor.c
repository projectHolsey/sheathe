/*
 * net_monitor.c — Passive HTTP (plain-text) traffic capture
 *
 * LIBRARY CHOICE: libpcap
 *   libpcap is the standard packet-capture library on Linux/macOS.
 *   It provides a clean API over raw AF_PACKET sockets and handles
 *   BPF (Berkeley Packet Filter) kernel-side filtering so we only
 *   receive relevant packets, reducing CPU overhead.
 *
 *   WHY NOT raw AF_PACKET sockets directly?
 *     We would have to write the BPF filter bytecode ourselves.
 *     libpcap compiles a human-readable filter string ("tcp port 80")
 *     into BPF for us.
 *
 *   WHY NOT nfqueue / iptables?
 *     nfqueue can intercept and modify packets but requires root and
 *     iptables rules. libpcap is read-only (passive) and simpler.
 *
 *   Install: sudo apt install libpcap-dev
 *   Link:    -lpcap
 */

#include "net_monitor.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <pcap/pcap.h>

/* ── data structures ──────────────────────────────────────────────────── */

typedef struct {
    char   timestamp[32];
    char   src_ip[48];
    char   dst_ip[48];
    int    src_port;
    int    dst_port;
    char   method[8];     /* GET, POST, … or "" if we couldn't parse HTTP */
    char   host[128];
    char   uri[256];
    int    length;        /* payload bytes */
} HttpEvent;

/* Simple fixed-size ring buffer — no malloc on the hot path */
static HttpEvent  g_events[MAX_EVENTS];
static int        g_head   = 0;   /* next write position */
static int        g_count  = 0;   /* total events captured */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static pcap_t    *g_handle  = NULL;
static char       g_iface[64] = "any";  /* default: all interfaces */
static pthread_t  g_thread;

/* ── packet parsing ───────────────────────────────────────────────────── */

/*
 * Ethernet header is 14 bytes.
 * IP header is at least 20 bytes (IHL field tells us actual size).
 * TCP header is at least 20 bytes (data offset field tells us actual size).
 *
 * We look for the HTTP request line in the TCP payload.
 * This works for plain HTTP only — TLS payloads are encrypted.
 */

#define ETHER_HDR 14

/* Crude IP header struct (big-endian fields, network byte order) */
typedef struct {
    uint8_t  ihl_ver;    /* version (4 bits) + IHL (4 bits) */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;      /* 6 = TCP */
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} IpHdr;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;   /* upper 4 bits = data offset in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} TcpHdr;

static void packet_handler(u_char *user,
                            const struct pcap_pkthdr *hdr,
                            const u_char *pkt)
{
    (void)user;

    if (hdr->caplen < ETHER_HDR + 20 + 20) return;  /* too short */

    /* Skip Ethernet header */
    const IpHdr *ip = (const IpHdr *)(pkt + ETHER_HDR);
    if (ip->proto != 6) return;  /* not TCP */

    int ip_hdr_len = (ip->ihl_ver & 0x0F) * 4;

    const TcpHdr *tcp = (const TcpHdr *)((const u_char *)ip + ip_hdr_len);
    int tcp_hdr_len = ((tcp->data_off >> 4) & 0x0F) * 4;

    /* Pointer to TCP payload */
    const u_char *payload = (const u_char *)tcp + tcp_hdr_len;
    int payload_len = (int)hdr->caplen
                      - ETHER_HDR - ip_hdr_len - tcp_hdr_len;

    if (payload_len <= 0) return;

    /* Only care about HTTP request methods in plaintext */
    const char *methods[] = {"GET ", "POST ", "PUT ", "DELETE ",
                              "PATCH ", "HEAD ", "OPTIONS ", NULL};
    int is_http = 0;
    for (int i = 0; methods[i]; i++) {
        if (payload_len >= (int)strlen(methods[i]) &&
            memcmp(payload, methods[i], strlen(methods[i])) == 0) {
            is_http = 1;
            break;
        }
    }
    if (!is_http) return;

    /* We have an HTTP request — populate an event */
    HttpEvent ev;
    memset(&ev, 0, sizeof(ev));

    /* Timestamp */
    time_t t = hdr->ts.tv_sec;
    struct tm *tm = gmtime(&t);
    strftime(ev.timestamp, sizeof(ev.timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    /* IP addresses */
    struct in_addr sa = { .s_addr = ip->saddr };
    struct in_addr da = { .s_addr = ip->daddr };
    snprintf(ev.src_ip, sizeof(ev.src_ip), "%s", inet_ntoa(sa));
    snprintf(ev.dst_ip, sizeof(ev.dst_ip), "%s", inet_ntoa(da));
    ev.src_port = ntohs(tcp->sport);
    ev.dst_port = ntohs(tcp->dport);
    ev.length   = payload_len;

    /* Parse first line: METHOD SP URI SP HTTP/x.x */
    char line[512];
    int llen = payload_len < 511 ? payload_len : 511;
    memcpy(line, payload, llen);
    line[llen] = '\0';

    char *nl = strpbrk(line, "\r\n");
    if (nl) *nl = '\0';

    sscanf(line, "%7s %255s", ev.method, ev.uri);

    /* Extract Host header if present */
    const char *host_hdr = memmem(payload, payload_len, "Host: ", 6);
    if (host_hdr) {
        host_hdr += 6;
        const char *end = strpbrk(host_hdr, "\r\n");
        int hlen = end ? (int)(end - host_hdr) : 0;
        if (hlen > 0 && hlen < (int)sizeof(ev.host)) {
            memcpy(ev.host, host_hdr, hlen);
            ev.host[hlen] = '\0';
        }
    }

    /* Store in ring buffer */
    pthread_mutex_lock(&g_lock);
    g_events[g_head] = ev;
    g_head = (g_head + 1) % MAX_EVENTS;
    if (g_count < MAX_EVENTS) g_count++;
    pthread_mutex_unlock(&g_lock);
}

/* ── capture thread ───────────────────────────────────────────────────── */

static void *capture_thread(void *arg)
{
    (void)arg;
    /* Loop forever, calling packet_handler for each matching packet.
     * pcap_loop blocks inside the kernel — very CPU-efficient. */
    pcap_loop(g_handle, -1, packet_handler, NULL);
    return NULL;
}

/* ── public API ───────────────────────────────────────────────────────── */

void net_init(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the interface in promiscuous mode so we see all traffic,
     * not just packets addressed to our MAC. */
    g_handle = pcap_open_live(g_iface, 65535, 1, 100, errbuf);
    if (!g_handle) {
        fprintf(stderr, "net_monitor: pcap_open_live: %s\n", errbuf);
        fprintf(stderr, "  (try running as root, or: sudo setcap cap_net_raw+eip ./sysmon)\n");
        return;
    }

    /* BPF filter: only capture TCP on ports 80, 8080, 3000, 8000.
     * The filter runs inside the kernel, so unmatched packets never
     * reach userspace — much faster than filtering in C. */
    struct bpf_program fp;
    const char *filter = "tcp and (port 80 or port 8080 or port 3000 or port 8000)";
    if (pcap_compile(g_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_handle, &fp) < 0) {
        fprintf(stderr, "net_monitor: filter error: %s\n", pcap_geterr(g_handle));
    }
    pcap_freecode(&fp);

    pthread_create(&g_thread, NULL, capture_thread, NULL);
    pthread_detach(g_thread);

    printf("net_monitor: capturing on '%s'\n", g_iface);
}

/* Called by POST /api/net/config with body like {"interface":"eth0"} */
void net_config(const char *json_body)
{
    if (!json_body) return;

    /* Minimal JSON field extraction — no external JSON lib needed for
     * a single-field config payload.
     * Alternative: cJSON (MIT, single-file) if configs become complex. */
    const char *p = strstr(json_body, "\"interface\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '"') p++;
    char iface[64];
    int i = 0;
    while (*p && *p != '"' && *p != '}' && i < 63)
        iface[i++] = *p++;
    iface[i] = '\0';
    if (i == 0) return;

    /* Restart capture on the new interface */
    if (g_handle) { pcap_breakloop(g_handle); pcap_close(g_handle); }
    snprintf(g_iface, sizeof(g_iface), "%s", iface);

    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(g_iface, 65535, 1, 100, errbuf);
    if (g_handle) {
        pthread_create(&g_thread, NULL, capture_thread, NULL);
        pthread_detach(g_thread);
        printf("net_monitor: switched to interface '%s'\n", g_iface);
    }
}

/* Serialise the ring buffer to JSON */
void net_get_json(char *out, int maxlen)
{
    pthread_mutex_lock(&g_lock);

    int pos = 0;
    pos += snprintf(out + pos, maxlen - pos,
                    "{\"interface\":\"%s\",\"events\":[", g_iface);

    /* Walk ring buffer in chronological order */
    int start = g_count < MAX_EVENTS ? 0 : g_head;
    int n     = g_count < MAX_EVENTS ? g_count : MAX_EVENTS;

    for (int i = 0; i < n && pos < maxlen - 256; i++) {
        const HttpEvent *e = &g_events[(start + i) % MAX_EVENTS];
        if (i > 0) pos += snprintf(out + pos, maxlen - pos, ",");
        pos += snprintf(out + pos, maxlen - pos,
            "{\"ts\":\"%s\",\"src\":\"%s:%d\",\"dst\":\"%s:%d\","
            "\"method\":\"%s\",\"host\":\"%s\",\"uri\":\"%s\","
            "\"len\":%d}",
            e->timestamp, e->src_ip, e->src_port,
            e->dst_ip, e->dst_port,
            e->method, e->host, e->uri, e->length);
    }

    pos += snprintf(out + pos, maxlen - pos, "]}");
    pthread_mutex_unlock(&g_lock);
}