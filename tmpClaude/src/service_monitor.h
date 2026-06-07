#ifndef SERVICE_MONITOR_H
#define SERVICE_MONITOR_H

void service_init(void);
void service_watch(const char *json_body);
void service_unwatch(const char *json_body);
void service_get_json(char *out, int maxlen);

#endif /* SERVICE_MONITOR_H */
