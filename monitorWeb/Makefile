# Makefile for net_monitor
#
# Targets:
#   make standalone   — builds ./net_monitor (demo, uses built-in printer)
#   make example      — builds ./my_monitor  (your code embedding the module)
#   make all          — builds both
#   make clean        — removes binaries and object files

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g

.PHONY: all standalone example clean

all: standalone example

# ── Standalone demo ────────────────────────────────────────────────────────
# -DNET_MONITOR_STANDALONE compiles in the main() at the bottom of
# net_monitor.c so the file is both a library and a runnable program.
standalone: net_monitor.c net_monitor.h
	$(CC) $(CFLAGS) -DNET_MONITOR_STANDALONE -o net_monitor net_monitor.c
	@echo "Built: ./net_monitor  (usage: ./net_monitor [bind_ip] [port])"

# ── Embedded-module example ────────────────────────────────────────────────
# No -DNET_MONITOR_STANDALONE, so net_monitor.c exports only functions.
# Your code in example.c provides main().
example: example.c net_monitor.c net_monitor.h
	$(CC) $(CFLAGS) -o my_monitor example.c net_monitor.c
	@echo "Built: ./my_monitor  (listens on 0.0.0.0:8888)"

clean:
	rm -f net_monitor my_monitor *.o
