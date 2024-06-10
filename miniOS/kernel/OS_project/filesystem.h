#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#define MAX_FILES 100

typedef struct File {
    char name[256];
    int is_directory;
    struct File *parent;
    struct File *children[MAX_FILES];
    int num_children;
    char *content;
} File;

extern File *root;

void initialize_file_system();
File *create_directory(const char *name, File *parent);
File *create_file(const char *name, File *parent);
File *find_directory(const char *path);
File *find_file_or_directory(const char *path); // 파일이나 디렉토리를 찾는 함수
File *create_directory_recursive(const char *path);
File *create_directory_by_path(const char *path);
void print_directory(File *dir, int depth);
int delete_directory(File *dir);
int delete_file(File *file);

#endif // FILESYSTEM_H

