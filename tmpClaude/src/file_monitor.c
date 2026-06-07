/*
 * file_monitor.c — Filesystem event monitoring via Linux inotify
 *
 * LIBRARY CHOICE: inotify (kernel API, no external library required)
 *   inotify is a Linux kernel subsystem that delivers filesystem events
 *   through a file descriptor.  You just read() from it.
 *
 *   WHY NOT libfam / gamin?
 *     Those are higher-level wrappers that add a daemon and IPC round-trip.
 *     For a self-contained tool, reading from inotify's fd directly is
 *     simpler, faster, and has no extra dependencies.
 *
 *   WHY NOT fanotify?
 *     fanotify can intercept and block file operations (useful for AV
 *     scanners).  inotify is read-only and sufficient for monitoring.
 *
 *   LIMITATIONS:
 *     - inotify does not recurse into subdirectories automatically.
 *       We add watches one level deep as a template; real recursion
 *       would use opendir/readdir + add watches for each subdir.
 *     - Watch count is limited by /proc/sys/fs/inotify/max_user_watches
 *       (default 8192).
 *
 * ── THIS FILE IS A TEMPLATE ──────────────────────────────────────────
 *   The caller already has their own file-monitoring logic.  This file
 *   shows the plumbing: how to add/remove watches and how to read events.
 *   Replace or extend the TODO sections with your own code.
 * ─────────────────────────────────────────────────────────────────────
 */

#include "file_monitor.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/inotify.h>

/* ── data structures ──────────────────────────────────────────────────── */

/* One watch entry: maps an inotify watch descriptor → path */
#define MAX_WATCHES 64

typedef struct {
    int  wd;           /* watch descriptor returned by inotify_add_watch */
    char path[256];
} WatchEntry;

typedef struct {
    char timestamp[32];
    char path[256];
    char event_type[32];  /* "create", "delete", "modify", "moved_from", etc. */
    char name[128];       /* filename within the watched directory */
} FileEvent;

static int         g_ifd      = -1;   /* inotify fd */
static WatchEntry  g_watches[MAX_WATCHES];
static int         g_nwatches = 0;

static FileEvent   g_events[MAX_EVENTS];
static int         g_head  = 0;
static int         g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_t   g_thread;

/* ── event loop ───────────────────────────────────────────────────────── */

/*
 * inotify delivers variable-length structs from read().
 * Each struct is: inotify_event header + optional name[namelen].
 */
static void *inotify_thread(void *arg)
{
    (void)arg;

    /* Buffer sized to hold several events at once.
     * The kernel coalesces events for efficiency. */
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    for (;;) {
        ssize_t n = read(g_ifd, buf, sizeof(buf));
        if (n <= 0) {
            if (errno == EAGAIN) continue;
            break;
        }

        const char *p = buf;
        while (p < buf + n) {
            const struct inotify_event *ie = (const struct inotify_event *)p;

            /* Find which path this watch descriptor belongs to */
            const char *wpath = "unknown";
            pthread_mutex_lock(&g_lock);
            for (int i = 0; i < g_nwatches; i++) {
                if (g_watches[i].wd == ie->wd) {
                    wpath = g_watches[i].path;
                    break;
                }
            }

            /* Translate inotify mask bits to a human-readable string */
            const char *etype = "unknown";
            if      (ie->mask & IN_CREATE)      etype = "create";
            else if (ie->mask & IN_DELETE)      etype = "delete";
            else if (ie->mask & IN_MODIFY)      etype = "modify";
            else if (ie->mask & IN_MOVED_FROM)  etype = "moved_from";
            else if (ie->mask & IN_MOVED_TO)    etype = "moved_to";
            else if (ie->mask & IN_ATTRIB)      etype = "attrib";
            else if (ie->mask & IN_CLOSE_WRITE) etype = "close_write";
            else if (ie->mask & IN_DELETE_SELF) etype = "delete_self";

            /* Store event */
            FileEvent *ev = &g_events[g_head];
            memset(ev, 0, sizeof(*ev));

            time_t t = time(NULL);
            struct tm *tm = gmtime(&t);
            strftime(ev->timestamp, sizeof(ev->timestamp),
                     "%Y-%m-%dT%H:%M:%SZ", tm);

            strncpy(ev->path,       wpath, sizeof(ev->path) - 1);
            strncpy(ev->event_type, etype, sizeof(ev->event_type) - 1);
            if (ie->len > 0)
                strncpy(ev->name, ie->name,
                        sizeof(ev->name) < ie->len ? sizeof(ev->name)-1 : ie->len);

            g_head = (g_head + 1) % MAX_EVENTS;
            if (g_count < MAX_EVENTS) g_count++;
            pthread_mutex_unlock(&g_lock);

            /* TODO: Insert your own processing here, e.g.:
             *   - hash-check the file for integrity monitoring
             *   - trigger an alert if a sensitive path changes
             *   - log to a database
             */

            p += sizeof(struct inotify_event) + ie->len;
        }
    }
    return NULL;
}

/* ── public API ───────────────────────────────────────────────────────── */

void file_init(void)
{
    /* Create the inotify instance */
    g_ifd = inotify_init1(IN_NONBLOCK);
    if (g_ifd < 0) {
        perror("file_monitor: inotify_init1");
        return;
    }

    pthread_create(&g_thread, NULL, inotify_thread, NULL);
    pthread_detach(g_thread);

    printf("file_monitor: ready (no paths watched yet)\n");
}

/* Called by POST /api/files/watch with body like {"path":"/var/log"} */
void file_watch(const char *json_body)
{
    if (!json_body || g_ifd < 0) return;

    /* Extract "path" from minimal JSON (same approach as net_config) */
    const char *p = strstr(json_body, "\"path\"");
    if (!p) return;
    p = strchr(p, ':'); if (!p) return; p++;
    while (*p == ' ' || *p == '"') p++;
    char path[256]; int i = 0;
    while (*p && *p != '"' && *p != '}' && i < 255) path[i++] = *p++;
    path[i] = '\0';
    if (i == 0) return;

    pthread_mutex_lock(&g_lock);

    if (g_nwatches >= MAX_WATCHES) {
        pthread_mutex_unlock(&g_lock);
        fprintf(stderr, "file_monitor: watch limit reached\n");
        return;
    }

    /* Watch for the most useful events — extend the mask as needed.
     *
     * IN_CLOSE_WRITE fires when a writer closes a file; more useful than
     * IN_MODIFY which fires on every write() syscall (very noisy for logs).
     */
    uint32_t mask = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
                  | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF;

    int wd = inotify_add_watch(g_ifd, path, mask);
    if (wd < 0) {
        perror("file_monitor: inotify_add_watch");
        pthread_mutex_unlock(&g_lock);
        return;
    }

    g_watches[g_nwatches].wd = wd;
    snprintf(g_watches[g_nwatches].path, sizeof(g_watches[g_nwatches].path), "%s", path);
    g_nwatches++;

    pthread_mutex_unlock(&g_lock);
    printf("file_monitor: watching '%s' (wd=%d)\n", path, wd);

    /* TODO: If path is a directory and you want recursive watching,
     * opendir(path), iterate, and call file_watch for each subdir. */
}

/* Called by POST /api/files/unwatch with body like {"path":"/var/log"} */
void file_unwatch(const char *json_body)
{
    if (!json_body || g_ifd < 0) return;

    const char *p = strstr(json_body, "\"path\"");
    if (!p) return;
    p = strchr(p, ':'); if (!p) return; p++;
    while (*p == ' ' || *p == '"') p++;
    char path[256]; int i = 0;
    while (*p && *p != '"' && *p != '}' && i < 255) path[i++] = *p++;
    path[i] = '\0';

    pthread_mutex_lock(&g_lock);
    for (int j = 0; j < g_nwatches; j++) {
        if (strcmp(g_watches[j].path, path) == 0) {
            inotify_rm_watch(g_ifd, g_watches[j].wd);
            /* Compact the array */
            g_watches[j] = g_watches[--g_nwatches];
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void file_get_json(char *out, int maxlen)
{
    pthread_mutex_lock(&g_lock);

    int pos = 0;
    pos += snprintf(out + pos, maxlen - pos, "{\"watches\":[");

    for (int i = 0; i < g_nwatches; i++) {
        if (i > 0) pos += snprintf(out + pos, maxlen - pos, ",");
        pos += snprintf(out + pos, maxlen - pos,
                        "\"%s\"", g_watches[i].path);
    }
    pos += snprintf(out + pos, maxlen - pos, "],\"events\":[");

    int start = g_count < MAX_EVENTS ? 0 : g_head;
    int n     = g_count < MAX_EVENTS ? g_count : MAX_EVENTS;

    for (int i = 0; i < n && pos < maxlen - 256; i++) {
        const FileEvent *e = &g_events[(start + i) % MAX_EVENTS];
        if (i > 0) pos += snprintf(out + pos, maxlen - pos, ",");
        pos += snprintf(out + pos, maxlen - pos,
            "{\"ts\":\"%s\",\"path\":\"%s\",\"type\":\"%s\",\"name\":\"%s\"}",
            e->timestamp, e->path, e->event_type, e->name);
    }

    pos += snprintf(out + pos, maxlen - pos, "]}");
    pthread_mutex_unlock(&g_lock);
}