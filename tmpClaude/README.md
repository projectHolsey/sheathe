# sysmon — Linux System Monitor

A self-contained system monitor: HTTP traffic, filesystem events, and service
logs/I/O — all in one local dashboard.  The backend is plain C; the frontend
is vanilla HTML/CSS/JS with no build step.

```
┌─────────────────────────────────────────────────────┐
│  Browser (index.html)                               │
│  polls /api/net, /api/files, /api/services every 2s │
└──────────────┬──────────────────────────────────────┘
               │ HTTP GET/POST (plain, no TLS)
┌──────────────▼──────────────────────────────────────┐
│  server.c  —  POSIX socket HTTP/1.1 server          │
│  Spawns one thread per connection (pthread)         │
├──────────┬──────────────┬───────────────────────────┤
│net_monitor│file_monitor  │service_monitor            │
│ (libpcap) │ (inotify)    │ (popen → systemctl/       │
│           │              │  journalctl / strace)     │
└──────────┴──────────────┴───────────────────────────┘
```

---

## Dependencies

| Library / Tool | Used in          | Install                        |
|----------------|------------------|--------------------------------|
| libpcap        | net_monitor.c    | `sudo apt install libpcap-dev` |
| inotify        | file_monitor.c   | Built into Linux kernel        |
| pthread        | all modules      | Part of glibc                  |
| strace         | service_monitor  | `sudo apt install strace`      |
| journalctl     | service_monitor  | Part of systemd                |

---

## Build

```bash
sudo apt install libpcap-dev strace
make
```

## Run

```bash
# Option A — run as root (simplest)
sudo ./sysmon

# Option B — grant only the needed capabilities
sudo setcap cap_net_raw+eip ./sysmon   # for pcap
# strace still needs root or CAP_SYS_PTRACE; skip I/O tracing otherwise
./sysmon
```

Open **http://127.0.0.1:8080** in your browser.

---

## Library choice rationale

### net_monitor — libpcap

**Chosen because:** It is the de-facto standard for packet capture on Linux and
macOS.  It compiles a human-readable BPF filter string into kernel bytecode so
unmatched packets never reach userspace.

**Alternatives:**
- *Raw `AF_PACKET` socket*: no dependency, but you write BPF bytecode manually.
- *libmicrohttpd / nfqueue*: wrong abstraction — those are for serving or
  intercepting packets, not passively sniffing.
- *eBPF (libbpf)*: lower overhead, stays in kernel, but requires kernel 5.8+
  and significantly more code.  Best choice for a production tool.

### file_monitor — inotify (no external library)

**Chosen because:** inotify is a Linux kernel API exposed through a plain file
descriptor.  You `read()` from it; no library needed.  It is fast, reliable,
and has been stable since Linux 2.6.13.

**Alternatives:**
- *fanotify*: can intercept and block file operations (useful for antivirus).
  Overkill for monitoring.
- *libfam / gamin*: adds a daemon and IPC round-trip for no benefit here.
- *inotify-tools*: CLI wrappers; not useful when embedding in C.

### service_monitor — popen() to systemctl / journalctl / strace

**Chosen because:** Spawning subprocesses keeps the code readable with zero
extra dependencies.  All three tools are universally available on systemd
systems.

**Alternatives for status:**
- `sd_unit_get_active_state()` from *libsystemd*: no shell, no subprocess,
  real-time push via D-Bus.  Add `-lsystemd` to LDFLAGS.

**Alternatives for log following:**
- `sd_journal_*` API from *libsystemd*: follow the journal via a file
  descriptor; better for production.

**Alternatives for I/O tracing:**
- *eBPF / bpftrace*: dramatically lower overhead; does not require ptrace.
  Strongly preferred in production.
- *ptrace() directly*: what strace uses under the hood.

### webserver — raw POSIX sockets

**Chosen because:** We only need GET/POST with plain HTTP, and the
implementation is ~100 lines that anyone can read and modify.

**Alternatives:**
- *libmicrohttpd*: full HTTP/1.1, TLS via GnuTLS, good API, production-ready.
- *mongoose*: single-file embeddable server with WebSocket support.  Great if
  you want to switch from polling to push.

---

## File structure

```
sysmon/
├── Makefile
├── README.md
├── src/
│   ├── server.c           HTTP server + request router
│   ├── server.h           Shared constants
│   ├── net_monitor.c/h    HTTP packet capture (libpcap)
│   ├── file_monitor.c/h   Filesystem events (inotify)  ← template
│   └── service_monitor.c/h  systemd status + logs + I/O trace
└── web/
    └── static/
        └── index.html     Dashboard UI (vanilla JS/CSS/HTML)
```

---

## API reference

| Method | Path                    | Body (JSON)             | Description                     |
|--------|-------------------------|-------------------------|---------------------------------|
| GET    | /api/net                | —                       | Last 256 HTTP events            |
| POST   | /api/net/config         | `{"interface":"eth0"}`  | Switch capture interface        |
| GET    | /api/files              | —                       | Watch list + last 256 events    |
| POST   | /api/files/watch        | `{"path":"/var/log"}`   | Add an inotify watch            |
| POST   | /api/files/unwatch      | `{"path":"/var/log"}`   | Remove a watch                  |
| GET    | /api/services           | —                       | All services: status+logs+I/O   |
| POST   | /api/services/watch     | `{"name":"nginx"}`      | Start monitoring a service      |
| POST   | /api/services/unwatch   | `{"name":"nginx"}`      | Stop monitoring a service       |
| GET    | /                       | —                       | Serves index.html               |

---

## Extending the file monitor

`file_monitor.c` is explicitly a **template**.  To add your own logic, look for
the `TODO` comments:

1. **Post-event processing** in `inotify_thread()` — hash the file, send an
   alert, write to a DB, etc.
2. **Recursive watching** — call `file_watch` for each subdirectory found by
   `opendir`/`readdir`.
3. **Persistence** — write events to SQLite (add `-lsqlite3`) instead of the
   in-memory ring buffer.
