#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

void file_init(void);
void file_watch(const char *json_body);
void file_unwatch(const char *json_body);
void file_get_json(char *out, int maxlen);

#endif /* FILE_MONITOR_H */
