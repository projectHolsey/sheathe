#ifndef NET_MONITOR_H
#define NET_MONITOR_H

/* Initialise pcap capture (call once at startup) */
void net_init(void);

/* Reconfigure interface from JSON body (POST /api/net/config) */
void net_config(const char *json_body);

/* Write current event ring buffer to `out` as JSON */
void net_get_json(char *out, int maxlen);

#endif /* NET_MONITOR_H */
