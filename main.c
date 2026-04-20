#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h> // For listing files in the current directory
#include "projectMonitor/monitor.h" // importing functionality for other library import


typedef struct {
    char filename;
    int fanotify_file_descriptor;
} fn_struct;

int main() {

    

    /**
     * 3 Main sections
     * 
     * 1 - Record the enviroment (changes to files)
     * 2 - Record the HTTP requests on a specific port / endpoint?
     *       - Can this be just pointed to a specific process?
     * 3 - Keep track of times that things changed / happened
     *  
     * Playback feature
     * - Set the environment back to a specific point in time
     * - Send off a specific command
     * - OR just viewer which lists the things that changed and the commmands that were sent without the additional
     *      - Maybe you have 'playback verbose/advanced' which will monitor more things or other locations too
     * 
     * Diff the before and after certain time periods
     * - Will come from good records
     */


    // At the start of day, record all files in the current directory
    // Can add more watchers later on to allow them to watch another file / directory
    DIR *d; 
    struct dirent *dir; // current directory
    
    d = opendir("."); // TODO : change to allow other directories / files
    if (d == NULL) {
        printf("Could not open current directory\n");
        return EXIT_FAILURE; // Failed to open the diretory
    }



    // Defining the array to hold the structs
    fn_struct *file_watchers = malloc(10 * sizeof(fn_struct));
    /* 
    TODO: This can be changed to allocate 100 file watchers or something so we don't need to waste time later 
    in the program allocating more memory to the heap.
    Could also be done at start of day so it's on the stack before we even start.
     */

    int numberOfWatchers = 1;
    int fileCounter = 0;
    // dir will already store the list of files in the current directory
    while ((dir == readdir(d))) {
        printf("Monitoring file : %s\n", dir->d_name); 
        if (numberOfWatchers <= fileCounter) {
            fn_struct *temp = realloc(file_watchers, (numberOfWatchers + 1) * sizeof(fn_struct));
            if (temp == NULL) {
                printf("Problem allocating more heap memory for list of file watcher");
            } else {
                
            }
        }

    }


    // recursively look at all files in the environment for changes to the env
    while(1) {



    }


}