#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h> // dirname과 basename 함수 사용을 위해 필요
#include "filesystem.h"
#include "syscall.h"

int deletedir(const char *dirpath) {
    // 경로 복사
    char *path_copy = strdup(dirpath);
    if (path_copy == NULL) {
        perror("strdup");
        return -1;
    }
    
    // dirname 사용을 위한 복사본 생성
    char *parent_dirpath_copy = strdup(dirpath);
    if (parent_dirpath_copy == NULL) {
        perror("strdup");
        free(path_copy);
        return -1;
    }
    char *parent_dirpath = dirname(parent_dirpath_copy);

    // basename 사용을 위한 복사본 생성
    char *dirname_copy = strdup(dirpath);
    if (dirname_copy == NULL) {
        perror("strdup");
        free(path_copy);
        free(parent_dirpath_copy);
        return -1;
    }
    char *dirname = basename(dirname_copy);

    // 부모 디렉터리 찾기
    File *parent_dir = find_directory(parent_dirpath);
    if (parent_dir == NULL || !parent_dir->is_directory) {
        printf("Error: Parent directory '%s' not found in virtual file system.\n", parent_dirpath);
        free(path_copy);
        free(parent_dirpath_copy);
        free(dirname_copy);
        return -1;
    }

    // 디렉토리 삭제
    int found = 0;
    for (int i = 0; i < parent_dir->num_children; i++) {
        if (parent_dir->children[i]->is_directory && strcmp(parent_dir->children[i]->name, dirname) == 0) {
            if (parent_dir->children[i]->num_children > 0) {
                printf("Error: Directory '%s' is not empty.\n", dirname);
                free(path_copy);
                free(parent_dirpath_copy);
                free(dirname_copy);
                return -1;
            }
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
    free(parent_dirpath_copy);
    free(dirname_copy);

    if (found) {
        printf("Directory '%s' deleted successfully from virtual file system.\n", dirpath);
        return 0;
    } else {
        printf("Error: Directory '%s' not found in virtual file system.\n", dirname);
        return -1;
    }
}

