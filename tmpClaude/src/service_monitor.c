/*
 * service_monitor.c — systemd service: status, log tailing, and I/O tracing
 *
 * THREE MECHANISMS used here:
 *
 * 1. STATUS — popen("systemctl is-active <name>")
 *    The simplest way to query systemd without linking against libsystemd.
 *    Alternatives:
 *      - sd_unit_get_active_state() from libsystemd: cleaner, no shell,
 *        but adds a dependency.  Fine choice for production.
 *      - D-Bus directly: very verbose, not worth it for a template.
 *
 * 2. LOGS — popen("journalctl -u <name> -n 50 --no-pager")
 *    journalctl is always available on systemd systems.
 *    Alternatives:
 *      - sd_journal_* API from libsystemd: lets you follow the journal
 *        in real-time via a file descriptor (sd_journal_get_fd).
 *        Better for a production tool; avoids spawning a subprocess.
 *      - Reading /var/log/syslog or /var/log/<service>.log directly:
 *        works for non-systemd systems.
 *
 * 3. I/O TRACING — popen("strace -p <pid> -e trace=read,write -s 128 -f")
 *    strace attaches to a running process and records syscalls.
 *    WHY strace?
 *      It is universally available, requires no code changes to the target,
 *      and the output is human-readable.
 *    Alternatives:
 *      - eBPF (bpftrace / libbpf): much lower overhead, stays in kernel,
 *        but requires a modern kernel (5.8+) and more setup.
 *        The right choice for production tracing.
 *      - /proc/<pid>/fd + inotify on the fd symlinks: can tell you which
 *        files are open, but not the data flowing through them.
 *      - ptrace() directly: what strace uses under the hood.  Very low-level.
 *
 * NOTE: strace needs CAP_SYS_PTRACE or root.
 *       journalctl may need the user to be in the 'systemd-journal' group.
 */

#include "service_monitor.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── data structures ──────────────────────────────────────────────────── */

#define MAX_SERVICES  16
#define MAX_LOG_LINES 200
#define LOG_LINE_LEN  256

typedef struct {
    char  name[64];
    char  status[32];          /* active / inactive / failed / unknown */

    /* Circular buffer of recent log lines */
    char  logs[MAX_LOG_LINES][LOG_LINE_LEN];
    int   log_head;
    int   log_count;

    /* I/O trace lines (strace output) */
    char  io[MAX_LOG_LINES][LOG_LINE_LEN];
    int   io_head;
    int   io_count;

    pthread_t log_thread;
    pthread_t io_thread;
    int       watching;        /* 1 = active, 0 = should stop */
} ServiceEntry;

static ServiceEntry  g_svcs[MAX_SERVICES];
static int           g_nsvc = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── helpers ──────────────────────────────────────────────────────────── */

/* Get the main PID of a systemd service via systemctl show */
static pid_t get_service_pid(const char *name)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "systemctl show -p MainPID --value %s 2>/dev/null", name);
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    pid_t pid = -1;
    if (fscanf(f, "%d", &pid) != 1) pid = -1;
    pclose(f);
    return (pid > 1) ? pid : -1;
}

/* ── log-following thread ─────────────────────────────────────────────── */

/*
 * We run "journalctl -u <name> -f --no-pager" (the -f flag means "follow",
 * like tail -f) in a subprocess and read its stdout line by line.
 * When the ServiceEntry's 'watching' flag is cleared we stop.
 */
typedef struct { ServiceEntry *svc; } ThreadArg;

static void *log_follow_thread(void *arg)
{
    ServiceEntry *s = ((ThreadArg *)arg)->svc;
    free(arg);

    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "journalctl -u %s -f --no-pager -n 50 2>&1", s->name);

    FILE *f = popen(cmd, "r");
    if (!f) return NULL;

    char line[LOG_LINE_LEN];
    while (s->watching && fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        line[strcspn(line, "\n")] = '\0';

        pthread_mutex_lock(&g_lock);
        snprintf(s->logs[s->log_head], LOG_LINE_LEN, "%s", line);
        s->log_head  = (s->log_head + 1) % MAX_LOG_LINES;
        if (s->log_count < MAX_LOG_LINES) s->log_count++;
        pthread_mutex_unlock(&g_lock);
    }

    pclose(f);
    return NULL;
}

/* ── I/O tracing thread ───────────────────────────────────────────────── */

static void *io_trace_thread(void *arg)
{
    ServiceEntry *s = ((ThreadArg *)arg)->svc;
    free(arg);

    pid_t pid = get_service_pid(s->name);
    if (pid <= 0) {
        pthread_mutex_lock(&g_lock);
        strncpy(s->io[s->io_head],
                "[io_trace] could not find service PID",
                LOG_LINE_LEN - 1);
        s->io_head = (s->io_head + 1) % MAX_LOG_LINES;
        if (s->io_count < MAX_LOG_LINES) s->io_count++;
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    /*
     * strace flags used:
     *   -p <pid>          attach to running process
     *   -e trace=read,write  only show read() and write() syscalls
     *   -s 128            show up to 128 chars of string arguments
     *   -f                follow child processes/threads
     *   -tt               microsecond timestamps
     *   2>&1              strace writes to stderr, redirect to stdout
     */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "strace -p %d -e trace=read,write -s 128 -f -tt 2>&1", (int)pid);

    FILE *f = popen(cmd, "r");
    if (!f) return NULL;

    char line[LOG_LINE_LEN];
    while (s->watching && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';

        pthread_mutex_lock(&g_lock);
        snprintf(s->io[s->io_head], LOG_LINE_LEN, "%s", line);
        s->io_head = (s->io_head + 1) % MAX_LOG_LINES;
        if (s->io_count < MAX_LOG_LINES) s->io_count++;
        pthread_mutex_unlock(&g_lock);
    }

    pclose(f);
    return NULL;
}

/* ── status polling thread ────────────────────────────────────────────── */

/*
 * Poll status every 5 seconds. We could use sd_journal or D-Bus to get
 * push notifications, but polling keeps things simple.
 */
static void *status_poll_thread(void *arg)
{
    ServiceEntry *s = ((ThreadArg *)arg)->svc;
    free(arg);

    while (s->watching) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "systemctl is-active %s 2>/dev/null", s->name);
        FILE *f = popen(cmd, "r");
        if (f) {
            char st[32] = "unknown";
            if (fgets(st, sizeof(st), f))
                st[strcspn(st, "\n")] = '\0';
            pclose(f);

            pthread_mutex_lock(&g_lock);
            snprintf(s->status, sizeof(s->status), "%s", st);
            pthread_mutex_unlock(&g_lock);
        }
        sleep(5);
    }
    return NULL;
}

/* ── public API ───────────────────────────────────────────────────────── */

void service_init(void)
{
    memset(g_svcs, 0, sizeof(g_svcs));
    printf("service_monitor: ready (no services watched yet)\n");
}

/* Called by POST /api/services/watch with body like {"name":"nginx"} */
void service_watch(const char *json_body)
{
    if (!json_body) return;

    const char *p = strstr(json_body, "\"name\"");
    if (!p) return;
    p = strchr(p, ':'); if (!p) return; p++;
    while (*p == ' ' || *p == '"') p++;
    char name[64]; int i = 0;
    while (*p && *p != '"' && *p != '}' && i < 63) name[i++] = *p++;
    name[i] = '\0';
    if (i == 0) return;

    pthread_mutex_lock(&g_lock);

    /* Check if already watching */
    for (int j = 0; j < g_nsvc; j++) {
        if (strcmp(g_svcs[j].name, name) == 0) {
            pthread_mutex_unlock(&g_lock);
            return;  /* already watching */
        }
    }

    if (g_nsvc >= MAX_SERVICES) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    ServiceEntry *s = &g_svcs[g_nsvc++];
    memset(s, 0, sizeof(*s));
    snprintf(s->name,   sizeof(s->name),   "%s", name);
    snprintf(s->status, sizeof(s->status), "%s", "unknown");
    s->watching = 1;

    pthread_mutex_unlock(&g_lock);

    /* Start the three monitoring threads */
    ThreadArg *a1 = malloc(sizeof(ThreadArg)); a1->svc = s;
    ThreadArg *a2 = malloc(sizeof(ThreadArg)); a2->svc = s;
    ThreadArg *a3 = malloc(sizeof(ThreadArg)); a3->svc = s;

    pthread_create(&s->log_thread, NULL, log_follow_thread,  a1);
    pthread_create(&s->io_thread,  NULL, io_trace_thread,    a2);
    pthread_t status_tid;
    pthread_create(&status_tid, NULL, status_poll_thread, a3);
    pthread_detach(status_tid);

    pthread_detach(s->log_thread);
    pthread_detach(s->io_thread);

    printf("service_monitor: watching '%s'\n", name);
}

/* Called by POST /api/services/unwatch with body like {"name":"nginx"} */
void service_unwatch(const char *json_body)
{
    if (!json_body) return;

    const char *p = strstr(json_body, "\"name\"");
    if (!p) return;
    p = strchr(p, ':'); if (!p) return; p++;
    while (*p == ' ' || *p == '"') p++;
    char name[64]; int i = 0;
    while (*p && *p != '"' && *p != '}' && i < 63) name[i++] = *p++;
    name[i] = '\0';

    pthread_mutex_lock(&g_lock);
    for (int j = 0; j < g_nsvc; j++) {
        if (strcmp(g_svcs[j].name, name) == 0) {
            g_svcs[j].watching = 0;  /* signal threads to stop */
            /* Compact the array */
            g_svcs[j] = g_svcs[--g_nsvc];
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void service_get_json(char *out, int maxlen)
{
    pthread_mutex_lock(&g_lock);

    int pos = 0;
    pos += snprintf(out + pos, maxlen - pos, "{\"services\":[");

    for (int j = 0; j < g_nsvc; j++) {
        const ServiceEntry *s = &g_svcs[j];
        if (j > 0) pos += snprintf(out + pos, maxlen - pos, ",");

        pos += snprintf(out + pos, maxlen - pos,
            "{\"name\":\"%s\",\"status\":\"%s\",\"logs\":[",
            s->name, s->status);

        /* Emit log lines in chronological order */
        int start = s->log_count < MAX_LOG_LINES ? 0 : s->log_head;
        int n     = s->log_count < MAX_LOG_LINES ? s->log_count : MAX_LOG_LINES;
        for (int k = 0; k < n && pos < maxlen - 512; k++) {
            const char *line = s->logs[(start + k) % MAX_LOG_LINES];
            if (k > 0) pos += snprintf(out + pos, maxlen - pos, ",");
            /* JSON-encode the string (escape backslash and double-quote) */
            pos += snprintf(out + pos, maxlen - pos, "\"");
            for (const char *c = line; *c && pos < maxlen - 8; c++) {
                if (*c == '"')       pos += snprintf(out+pos, 4, "\\\"");
                else if (*c == '\\') pos += snprintf(out+pos, 4, "\\\\");
                else if (*c == '\n') pos += snprintf(out+pos, 4, "\\n");
                else                 out[pos++] = *c;
            }
            pos += snprintf(out + pos, maxlen - pos, "\"");
        }

        pos += snprintf(out + pos, maxlen - pos, "],\"io\":[");

        /* Emit I/O trace lines */
        start = s->io_count < MAX_LOG_LINES ? 0 : s->io_head;
        n     = s->io_count < MAX_LOG_LINES ? s->io_count : MAX_LOG_LINES;
        for (int k = 0; k < n && pos < maxlen - 512; k++) {
            const char *line = s->io[(start + k) % MAX_LOG_LINES];
            if (k > 0) pos += snprintf(out + pos, maxlen - pos, ",");
            pos += snprintf(out + pos, maxlen - pos, "\"");
            for (const char *c = line; *c && pos < maxlen - 8; c++) {
                if (*c == '"')       pos += snprintf(out+pos, 4, "\\\"");
                else if (*c == '\\') pos += snprintf(out+pos, 4, "\\\\");
                else if (*c == '\n') pos += snprintf(out+pos, 4, "\\n");
                else                 out[pos++] = *c;
            }
            pos += snprintf(out + pos, maxlen - pos, "\"");
        }

        pos += snprintf(out + pos, maxlen - pos, "]}");
    }

    pos += snprintf(out + pos, maxlen - pos, "]}");
    pthread_mutex_unlock(&g_lock);
}