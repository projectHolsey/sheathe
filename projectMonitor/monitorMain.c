#include <stdio.h>
#include "monitor.h"
#include <unistd.h>



int main() {

    while(1) {

        sleep(1);

        int fd = watch_new_file("test.txt");
    
        print_path_from_fd(fd);
    }


    return 0;
}