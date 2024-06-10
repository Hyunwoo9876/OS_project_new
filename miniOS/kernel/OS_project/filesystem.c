#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesystem.h"

File *root;

void initialize_file_system() {
    root = (File *)malloc(sizeof(File));
    strcpy(root->name, "/");
    root->is_directory = 1;
    root->parent = NULL;
    root->num_children = 0;
    root->content = NULL;
}

File *create_directory(const char *name, File *parent) {
    if (parent->num_children >= MAX_FILES) {
        printf("Directory full\n");
        return NULL;
    }

    File *dir = (File *)malloc(sizeof(File));
    strcpy(dir->name, name);
    dir->is_directory = 1;
    dir->parent = parent;
    dir->num_children = 0;
    dir->content = NULL;

    parent->children[parent->num_children++] = dir;
    return dir;
}

File *create_file(const char *name, File *parent) {
    if (parent->num_children >= MAX_FILES) {
        printf("Directory full\n");
        return NULL;
    }

    File *file = (File *)malloc(sizeof(File));
    strcpy(file->name, name);
    file->is_directory = 0;
    file->parent = parent;
    file->content = (char *)malloc(1024); // 기본 크기 1024 바이트 할당
    file->content[0] = '\0';

    parent->children[parent->num_children++] = file;
    return file;
}

File *find_directory(const char *path) {
    if (strcmp(path, "/") == 0) {
        return root;
    }

    File *current = root;
    char *token = strtok(strdup(path), "/");

    while (token != NULL) {
        int found = 0;
        for (int i = 0; i < current->num_children; i++) {
            if (current->children[i]->is_directory && strcmp(current->children[i]->name, token) == 0) {
                current = current->children[i];
                found = 1;
                break;
            }
        }
        if (!found) {
            return NULL;
        }
        token = strtok(NULL, "/");
    }

    return current;
}

File *find_file_or_directory(const char *path) {
    if (strcmp(path, "/") == 0) {
        return root;
    }

    File *current = root;
    char *token = strtok(strdup(path), "/");

    while (token != NULL) {
        int found = 0;
        for (int i = 0; i < current->num_children; i++) {
            if (strcmp(current->children[i]->name, token) == 0) {
                current = current->children[i];
                found = 1;
                break;
            }
        }
        if (!found) {
            return NULL;
        }
        token = strtok(NULL, "/");
    }

    return current;
}

File *create_directory_recursive(const char *path) {
    if (strcmp(path, "/") == 0) {
        return root;
    }

    char *temp_path = strdup(path);
    char *token = strtok(temp_path, "/");
    File *current = root;

    while (token != NULL) {
        File *next_dir = NULL;
        for (int i = 0; i < current->num_children; i++) {
            if (current->children[i]->is_directory && strcmp(current->children[i]->name, token) == 0) {
                next_dir = current->children[i];
                break;
            }
        }
        if (next_dir == NULL) {
            next_dir = create_directory(token, current);
        }
        current = next_dir;
        token = strtok(NULL, "/");
    }

    free(temp_path);
    return current;
}

File *create_directory_by_path(const char *path) {
    return create_directory_recursive(path);
}

void print_directory(File *dir, int depth) {
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
    printf("%s/\n", dir->name);
    for (int i = 0; i < dir->num_children; i++) {
        if (dir->children[i]->is_directory) {
            print_directory(dir->children[i], depth + 1);
        } else {
            for (int j = 0; j < depth + 1; j++) {
                printf("  ");
            }
            printf("%s\n", dir->children[i]->name);
        }
    }
}

int delete_directory(File *dir) {
    if (dir == NULL || !dir->is_directory) {
        return -1;
    }

    for (int i = 0; i < dir->num_children; i++) {
        if (dir->children[i]->is_directory) {
            delete_directory(dir->children[i]);
        } else {
            free(dir->children[i]->content);
            free(dir->children[i]);
        }
    }

    free(dir);
    return 0;
}

int delete_file(File *file) {
    if (file == NULL || file->is_directory) {
        return -1;
    }

    free(file->content);
    free(file);
    return 0;
}

