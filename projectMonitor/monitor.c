#define _GNU_SOURCE // imports functions and static vars (e.g. PATH_MAX)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h> // file control headers
#include <string.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <sys/stat.h>



void print_exe_from_pid(pid_t pid)
{
    char exe_path[64];
    char resolved[PATH_MAX];

    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

    ssize_t len = readlink(exe_path, resolved, sizeof(resolved) - 1);
    if (len != -1) {
        resolved[len] = '\0';
        printf("Executable: %s\n", resolved);
    } else {
        printf("Executable: [unknown]\n");
    }

}

static void print_path_from_fd(int fd)
{
    char path[PATH_MAX];
    char proc_path[64];

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(proc_path, path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        printf("Path: %s\n", path);
    } else {
        perror("readlink");
    }
}

int watch_new_file(char* filename) {

    /* Initialize fanotify in notification mode (no permission events) */
    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC,
                               O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) {
        perror("fanotify_init");
        return -1;
    }

    /* Add mark for the specific file */
    if (fanotify_mark(fan_fd,
                      FAN_MARK_ADD,
                      FAN_OPEN | FAN_CLOSE_WRITE | FAN_MODIFY,
                      AT_FDCWD,
                      filename) == -1) {
        perror("fanotify_mark");
        close(fan_fd);
        return -1;
    } 

    return fan_fd; // 

}