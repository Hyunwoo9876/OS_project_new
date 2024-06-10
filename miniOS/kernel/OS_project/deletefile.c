#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h> // dirname과 basename 함수 사용을 위해 필요
#include "filesystem.h"
#include "syscall.h"

int deletefile(const char *filepath) {
    // 경로 복사
    char *path_copy = strdup(filepath);
    if (path_copy == NULL) {
        perror("strdup");
        return -1;
    }
    
    // dirname 사용을 위한 복사본 생성
    char *dirpath_copy = strdup(filepath);
    if (dirpath_copy == NULL) {
        perror("strdup");
        free(path_copy);
        return -1;
    }
    char *dirpath = dirname(dirpath_copy);

    // basename 사용을 위한 복사본 생성
    char *filename_copy = strdup(filepath);
    if (filename_copy == NULL) {
        perror("strdup");
        free(path_copy);
        free(dirpath_copy);
        return -1;
    }
    char *filename = basename(filename_copy);

    // 부모 디렉터리 찾기
    File *parent_dir = find_directory(dirpath);
    if (parent_dir == NULL || !parent_dir->is_directory) {
        printf("Error: Parent directory '%s' not found in virtual file system.\n", dirpath);
        free(path_copy);
        free(dirpath_copy);
        free(filename_copy);
        return -1;
    }

    // 파일 삭제
    int found = 0;
    for (int i = 0; i < parent_dir->num_children; i++) {
        if (!parent_dir->children[i]->is_directory && strcmp(parent_dir->children[i]->name, filename) == 0) {
            free(parent_dir->children[i]);
            for (int j = i; j < parent_dir->num_children - 1; j++) {
                parent_dir->children[j] = parent_dir->children[j + 1];
            }
            parent_dir->num_children--;
            found = 1;
            break;
        }
    }

    free(path_copy);
    free(dirpath_copy);
    free(filename_copy);

    if (found) {
        printf("File '%s' deleted successfully from virtual file system.\n", filepath);
        return 0;
    } else {
        printf("Error: File '%s' not found in virtual file system.\n", filename);
        return -1;
    }
}

