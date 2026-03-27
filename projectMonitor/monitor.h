#include <fcntl.h>
 
extern void print_exe_from_pid(pid_t pid);
static void print_path_from_fd(pid_t pid);