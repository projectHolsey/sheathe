/*
 * example.c — demonstrates embedding net_monitor in your own C program.
 *
 * This file shows three things:
 *   1. How to #include the module header.
 *   2. How to write your own on_packet callback.
 *   3. How to compile everything together.
 *
 * Compile:
 *   gcc -Wall -Wextra -o my_monitor example.c net_monitor.c
 *
 * Run:
 *   ./my_monitor
 *   # In another terminal: curl http://localhost:8888/test
 *   # Or:  echo "hello" | nc localhost 8888
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Include the monitor's public API.
 * Because net_monitor.h lives in the same directory we use "" not <>.
 * ("" → search relative to this file first, then system paths)
 * (<> → search system include paths only)
 */
#include "net_monitor.h"

/* ── Example 1: minimal callback — just count bytes ────────────────────── */

/*
 * A "user_data" struct we can pass through the monitor untouched.
 * The monitor holds a void* so we can put anything here.
 */
typedef struct {
    unsigned long total_bytes;
    unsigned long total_packets;
} Stats;

/*
 * my_packet_handler() is called by net_monitor for every received segment.
 *
 * Parameters:
 *   pkt       — all TCP metadata + payload (valid only during this call)
 *   user_data — whatever you put in cfg.user_data, cast back to your type
 *
 * The packet pointer is read-only; the buffer it points into is reused
 * after you return, so copy payload bytes if you need them later.
 */
static void my_packet_handler(const NetPacket *pkt, void *user_data)
{
    Stats *stats = (Stats *)user_data;

    stats->total_bytes   += pkt->payload_len;
    stats->total_packets += 1;

    /* --- Use the built-in pretty-printer for the full hex dump --- */
    net_packet_print(pkt);

    /* --- Then add our own extra line --- */
    printf("  [stats so far]  packets=%lu  bytes=%lu\n\n",
           stats->total_packets, stats->total_bytes);
}

/* ── Example 2: write raw packets to a file for later replay ─────────────
 *
 * Each record is a simple binary structure:
 *   [8 bytes: tv_sec][4 bytes: tv_nsec]
 *   [4 bytes: src_ip as uint32][2 bytes: src_port]
 *   [4 bytes: dst_ip as uint32][2 bytes: dst_port]
 *   [4 bytes: seq][4 bytes: ack][2 bytes: window]
 *   [1 byte: flags][1 byte: data_offset]
 *   [4 bytes: payload_len][payload_len bytes: payload]
 *
 * A replay tool reads this file and crafts raw IP+TCP headers from each
 * record, then sends via sendto() on an AF_INET / SOCK_RAW socket.
 *
 * Uncomment the file-writing block in main() to activate this.
 */
static void write_packet_to_file(const NetPacket *pkt, void *user_data)
{
    FILE *f = (FILE *)user_data;
    if (!f) return;

    /* Timestamps */
    int64_t  tv_sec  = (int64_t)pkt->arrived_at.tv_sec;
    uint32_t tv_nsec = (uint32_t)pkt->arrived_at.tv_nsec;
    fwrite(&tv_sec,  sizeof(tv_sec),  1, f);
    fwrite(&tv_nsec, sizeof(tv_nsec), 1, f);

    /* Addressing — store as text (simplest cross-platform format) */
    uint8_t src_ip_len = (uint8_t)strlen(pkt->src_ip);
    uint8_t dst_ip_len = (uint8_t)strlen(pkt->dst_ip);
    fwrite(&src_ip_len,  1, 1, f);
    fwrite(pkt->src_ip,  1, src_ip_len, f);
    fwrite(&pkt->src_port, sizeof(pkt->src_port), 1, f);
    fwrite(&dst_ip_len,  1, 1, f);
    fwrite(pkt->dst_ip,  1, dst_ip_len, f);
    fwrite(&pkt->dst_port, sizeof(pkt->dst_port), 1, f);

    /* TCP header fields */
    fwrite(&pkt->seq,         sizeof(pkt->seq),         1, f);
    fwrite(&pkt->ack,         sizeof(pkt->ack),         1, f);
    fwrite(&pkt->window,      sizeof(pkt->window),      1, f);
    fwrite(&pkt->flags,       sizeof(pkt->flags),       1, f);
    fwrite(&pkt->data_offset, sizeof(pkt->data_offset), 1, f);

    /* Payload */
    uint32_t plen = (uint32_t)pkt->payload_len;
    fwrite(&plen,         sizeof(plen), 1, f);
    fwrite(pkt->payload,  1, plen,      f);

    fflush(f);  /* so the file is usable even if we crash */

    /* Also print to screen */
    net_packet_print(pkt);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    /* --- Option A: print-only callback with stats --- */
    Stats stats = {0};

    NetMonitorConfig cfg = {
        .bind_ip   = "0.0.0.0",   /* listen on all interfaces */
        .port      = 8888,
        .max_conns = 8,
        .on_packet = my_packet_handler,
        .user_data = &stats,
    };

    /* --- Option B: write packets to a binary capture file ---
     *   Uncomment this block (and comment out Option A's cfg) to activate.
     *
     *   FILE *cap = fopen("capture.bin", "wb");
     *   if (!cap) { perror("fopen"); return 1; }
     *
     *   NetMonitorConfig cfg = {
     *       .bind_ip   = "0.0.0.0",
     *       .port      = 8888,
     *       .max_conns = 8,
     *       .on_packet = write_packet_to_file,
     *       .user_data = cap,
     *   };
     *   int rc = net_monitor_run(&cfg);
     *   fclose(cap);
     *   return rc;
     */

    return net_monitor_run(&cfg);
}
