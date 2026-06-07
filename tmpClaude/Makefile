# Makefile for sysmo
#
# Dependencies:
#   libpcap-dev  (net_monitor)   — sudo apt install libpcap-dev
#   libpthread   (all modules)   — included in glibc
#   inotify      (file_monitor)  — built into the Linux kernel, no extra pkg
#   strace        (service I/O)  — sudo apt install strace
#
# Build:   make
# Clean:   make clean
# Run:     sudo ./sysmon        (sudo needed for pcap raw socket + strace)
#          OR: sudo setcap cap_net_raw+eip ./sysmon && ./sysmon

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -Isrc
LDFLAGS = -lpthread -lpcap

SRCS = src/server.c \
       src/net_monitor.c \
       src/file_monitor.c \
       src/service_monitor.c

TARGET = sysmon

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
