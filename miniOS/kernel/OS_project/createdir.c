#include <stdio.h>
#include "filesystem.h"
#include "syscall.h"

void createdir(const char *path) {
    File *new_dir = create_directory_by_path(path);
    if (new_dir != NULL) {
        printf("Directory '%s' created successfully.\n", path);
    } else {
        printf("Error creating directory '%s'.\n", path);
    }
}

