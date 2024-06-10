#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h> // for dirname and basename
#include "filesystem.h"
#include "syscall.h"

int createfile(const char *filepath) {
    // 가상 파일 시스템에 파일 생성
    char *path_copy = strdup(filepath);
    char *dirpath = dirname(path_copy);

    // strdup를 사용하여 basename의 인수 타입을 맞추기
    char *filename_copy = strdup(filepath);
    char *filename = basename(filename_copy);

    File *parent_dir = find_directory(dirpath);

    if (parent_dir == NULL || !parent_dir->is_directory) {
        printf("Error: Parent directory '%s' not found in virtual file system.\n", dirpath);
        free(path_copy);
        free(filename_copy);
        return -1;
    }

    create_file(filename, parent_dir);

    printf("File '%s' created successfully in virtual file system.\n", filepath);
    free(path_copy);
    free(filename_copy);
    return 0;
}
