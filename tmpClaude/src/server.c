/*
 * server.c — Minimal HTTP/1.1 webserver (plain C, POSIX sockets only)
 *
 * WHY no external HTTP lib?
 *   For a monitoring tool we only need GET/POST, no TLS, no HTTP/2.
 *   A raw socket loop is ~100 lines and has zero dependencies.
 *   Alternatives: libmicrohttpd (full-featured, good for prod),
 *   mongoose (single-file, embeddable). Both are excellent if you
 *   later need TLS or WebSockets.
 *
 * Compile: gcc -o sysmon server.c net_monitor.c file_monitor.c \
 *               service_monitor.c -lpthread -lpcap
 */

#include "server.h"
#include "net_monitor.h"
#include "file_monitor.h"
#include "service_monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define PORT        8080
#define BACKLOG     16
#define BUF_SIZE    8192
#define RESP_SIZE   65536

/* ── helpers ──────────────────────────────────────────────────────────── */

/* Send a complete HTTP response.
 * status_line: e.g. "200 OK"
 * content_type: e.g. "application/json"
 * body: null-terminated string */
static void send_response(int fd,
                          const char *status_line,
                          const char *content_type,
                          const char *body)
{
    char header[512];
    int  body_len = body ? (int)strlen(body) : 0;

    /* HTTP/1.1 requires Content-Length so the client knows when the
     * body ends without relying on connection close. */
    snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"   /* allow the browser to call us */
        "Connection: close\r\n"
        "\r\n",
        status_line, content_type, body_len);

    ssize_t _w;
    _w = write(fd, header, strlen(header)); (void)_w;
    if (body_len > 0) { _w = write(fd, body, body_len); (void)_w; }
}

/* Serve a static file from web/static/.
 * Returns 0 on success, -1 if file not found. */
static int serve_static(int fd, const char *path)
{
    /* Map URL path → filesystem path */
    char fspath[512];
    /* Serve from the directory next to the binary */
    snprintf(fspath, sizeof(fspath), "web/static%s",
             strcmp(path, "/") == 0 ? "/index.html" : path);

    FILE *f = fopen(fspath, "rb");
    if (!f) return -1;

    /* Crude MIME detection — extend as needed */
    const char *mime = "application/octet-stream";
    if (strstr(fspath, ".html")) mime = "text/html; charset=utf-8";
    else if (strstr(fspath, ".css"))  mime = "text/css";
    else if (strstr(fspath, ".js"))   mime = "application/javascript";

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t _r = fread(buf, 1, sz, f); (void)_r;
    buf[sz] = '\0';
    fclose(f);

    send_response(fd, "200 OK", mime, buf);
    free(buf);
    return 0;
}

/* ── request dispatcher ───────────────────────────────────────────────── */

/*
 * Very small router.  We only look at the first line of the HTTP request
 * (METHOD /path HTTP/1.x) and dispatch to the right monitor module.
 *
 * A production router would parse headers, query-strings, and a body
 * properly.  Here we keep it minimal so every line is understandable.
 */
static void handle_request(int fd, const char *raw)
{
    /* Parse first line: METHOD SP path SP version CRLF */
    char method[8], path[256], version[16];
    if (sscanf(raw, "%7s %255s %15s", method, path, version) < 2) {
        send_response(fd, "400 Bad Request", "text/plain", "bad request");
        return;
    }

    /* Find the body (after the blank line "\r\n\r\n") */
    const char *body_start = strstr(raw, "\r\n\r\n");
    if (body_start) body_start += 4;

    /* ── API routes ── */
    if (strcmp(method, "GET") == 0) {

        char resp[RESP_SIZE];

        if (strcmp(path, "/api/net") == 0) {
            net_get_json(resp, sizeof(resp));
            send_response(fd, "200 OK", "application/json", resp);

        } else if (strcmp(path, "/api/files") == 0) {
            file_get_json(resp, sizeof(resp));
            send_response(fd, "200 OK", "application/json", resp);

        } else if (strcmp(path, "/api/services") == 0) {
            service_get_json(resp, sizeof(resp));
            send_response(fd, "200 OK", "application/json", resp);

        } else {
            /* Fall through to static files */
            if (serve_static(fd, path) < 0)
                send_response(fd, "404 Not Found", "text/plain", "not found");
        }

    } else if (strcmp(method, "POST") == 0) {

        /* Control endpoints let the UI tell us what to watch */
        if (strcmp(path, "/api/net/config") == 0) {
            net_config(body_start);       /* e.g. {"interface":"eth0"} */
            send_response(fd, "200 OK", "application/json", "{\"ok\":true}");

        } else if (strcmp(path, "/api/files/watch") == 0) {
            file_watch(body_start);       /* e.g. {"path":"/var/log"} */
            send_response(fd, "200 OK", "application/json", "{\"ok\":true}");

        } else if (strcmp(path, "/api/files/unwatch") == 0) {
            file_unwatch(body_start);
            send_response(fd, "200 OK", "application/json", "{\"ok\":true}");

        } else if (strcmp(path, "/api/services/watch") == 0) {
            service_watch(body_start);    /* e.g. {"name":"nginx"} */
            send_response(fd, "200 OK", "application/json", "{\"ok\":true}");

        } else if (strcmp(path, "/api/services/unwatch") == 0) {
            service_unwatch(body_start);
            send_response(fd, "200 OK", "application/json", "{\"ok\":true}");

        } else {
            send_response(fd, "404 Not Found", "text/plain", "not found");
        }

    } else {
        send_response(fd, "405 Method Not Allowed", "text/plain", "method not allowed");
    }
}

/* ── per-connection thread ────────────────────────────────────────────── */

/*
 * WHY a thread per connection?
 *   Simple and correct for a low-concurrency monitoring dashboard.
 *   The browser polls every few seconds; we rarely have >2 concurrent
 *   connections.
 *
 *   Alternatives:
 *     - epoll event loop (libuv-style): more scalable but far more complex.
 *     - thread pool: good middle ground for medium load.
 *   For a local dashboard, one thread per connection is perfectly fine.
 */
static void *conn_thread(void *arg)
{
    int fd = *(int *)arg;
    free(arg);

    char buf[BUF_SIZE];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        handle_request(fd, buf);
    }

    close(fd);
    return NULL;
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Initialise each monitor subsystem */
    net_init();
    file_init();
    service_init();

    /* Create a TCP socket */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    /* Allow rapid restart without "Address already in use" */
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY,   /* listen on all interfaces */
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, BACKLOG);

    printf("sysmon listening on http://127.0.0.1:%d\n", PORT);

    for (;;) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int cfd = accept(srv, (struct sockaddr *)&client, &clen);
        if (cfd < 0) { perror("accept"); continue; }

        /* Hand off to a thread so the accept loop never blocks */
        int *arg = malloc(sizeof(int));
        *arg = cfd;
        pthread_t tid;
        pthread_create(&tid, NULL, conn_thread, arg);
        pthread_detach(tid);   /* we don't join — thread cleans itself up */
    }

    close(srv);
    return 0;
}