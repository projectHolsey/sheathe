#include <stdio.h>
#include <string.h>
#include <stdlib.h>


// This should rarely exceed this amount.. But we can calloc more if needed later on.
char env_vars[100][100];

/**
 * In here we're looking for things like..:
 *  - Environmental variable changes
 *  - Services and statuses
 *  - Log files
 *  - 
 * 
 */
void sys_monitor_main() {

}


void check_env_vars() {

    FILE *fp;
    char buffer[1024];

    char cmd[50] = {"printenv"};

    fp = popen(cmd, "r"); 
    if (fp == NULL) {
        printf("Error collecting env vars, from 'printev' command");
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }

    // Closing the pipe to the executed command
    int status = pclose(fp);
    if (status == -1) {
        printf("Error closing pipe\n");
    } else {
        printf("\nCommand exited with status: %d\n", status);
    }

    return;

}

