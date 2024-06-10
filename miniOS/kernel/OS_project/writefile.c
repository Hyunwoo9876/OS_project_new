#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "filesystem.h"
#include "syscall.h"

int writefile() {
    char filepath[256];
    printf("Enter filename: ");
    scanf("%255s", filepath);  // 파일 이름 입력 받기 (최대 255자)

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

    // 파일 찾기
    File *file = NULL;
    for (int i = 0; i < parent_dir->num_children; i++) {
        if (!parent_dir->children[i]->is_directory && strcmp(parent_dir->children[i]->name, filename) == 0) {
            file = parent_dir->children[i];
            break;
        }
    }

    // 파일이 존재하지 않으면 생성
    if (file == NULL) {
        file = create_file(filename, parent_dir);
        if (file == NULL) {
            printf("Error: Could not create file '%s'.\n", filename);
            free(path_copy);
            free(dirpath_copy);
            free(filename_copy);
            return -1;
        }
    }

    // 파일 내용 입력 받기
    char buffer[256];
    printf("Enter content to write (max 255 characters): ");
    scanf(" %[^\n]", buffer);  // 파일 내용 입력 받기 (공백 포함하여 한 줄)

    // 파일 내용 추가
    if (file->content == NULL) {
        file->content = strdup(buffer);
    } else {
        char *new_content = (char *)malloc(strlen(file->content) + strlen(buffer) + 1);
        if (new_content == NULL) {
            perror("malloc");
            free(path_copy);
            free(dirpath_copy);
            free(filename_copy);
            return -1;
        }
        strcpy(new_content, file->content);
        strcat(new_content, buffer);
        free(file->content);
        file->content = new_content;
    }

    printf("Content written to file '%s' successfully.\n", filepath);
    free(path_copy);
    free(dirpath_copy);
    free(filename_copy);
    return strlen(buffer);
}

