#include "process.h"
#include "filesystem.h"
#include <stdio.h>
#include <string.h>

Process process_table[MAX_PROCESSES];
int process_count = 0;

void initialize_process(Process *process, int pid, const char *name) {
    process->pid = pid;
    strncpy(process->name, name, sizeof(process->name));
    process->state = READY;
    process->priority = 0;
    process->pc = 0;
    memset(process->stack, 0, STACK_SIZE);
    process->parent = NULL;
    process->arrival_time = 0;
    process->remaining_time = 0;
}

Process* create_process(const char *name, int priority) {
    if (process_count >= MAX_PROCESSES) {
        printf("Error: Maximum number of processes reached.\n");
        return NULL;
    }

    Process *process = &process_table[process_count++];
    initialize_process(process, process_count, name);
    process->priority = priority;
    printf("Process %s created with PID %d.\n", name, process->pid);
    return process;
}

Process* fork_process(Process *parent) {
    if (process_count >= MAX_PROCESSES) {
        printf("Error: Maximum number of processes reached.\n");
        return NULL;
    }

    Process *process = &process_table[process_count++];
    initialize_process(process, process_count, parent->name);
    process->priority = parent->priority;
    process->parent = parent;
    memcpy(process->stack, parent->stack, STACK_SIZE);
    process->pc = parent->pc;
    printf("Process %s forked with PID %d.\n", process->name, process->pid);
    return process;
}

void schedule() {
    static int current_process_idx = 0;
    if (process_count == 0) {
        return;
    }

    process_table[current_process_idx].state = READY;
    current_process_idx = (current_process_idx + 1) % process_count;
    process_table[current_process_idx].state = RUNNING;

    printf("Scheduled process %s (PID %d).\n", process_table[current_process_idx].name, process_table[current_process_idx].pid);
}

void terminate_process(Process *process) {
    process->state = TERMINATED;
    printf("Process %s (PID %d) terminated.\n", process->name, process->pid);
}

int process_open_file(Process *process, const char *path) {
    File *file = find_file_or_directory(path);
    if (file == NULL || file->is_directory) {
        printf("Error: File not found or is a directory.\n");
        return -1;
    }
    int fd = (int)(file - root); // 파일 디스크립터로 파일 포인터를 변환
    return fd;
}

int process_close_file(Process *process, int fd) {
    return 0;
}

ssize_t process_read_file(Process *process, const char *path, void *buf, size_t count) {
    File *file = find_file_or_directory(path); // 파일 경로로 파일을 찾음
    if (file == NULL || file->is_directory) {
        printf("Error: Invalid file descriptor or is a directory.\n");
        return -1;
    }
    strncpy(buf, file->content, count);
    return strlen(file->content);
}

ssize_t process_write_file(Process *process, int fd, const void *buf, size_t count) {
    File *file = root + fd; // 파일 디스크립터로 파일 포인터를 변환
    if (file == NULL || file->is_directory) {
        printf("Error: Invalid file descriptor or is a directory.\n");
        return -1;
    }
    strncpy(file->content, buf, count);
    return count;
}

