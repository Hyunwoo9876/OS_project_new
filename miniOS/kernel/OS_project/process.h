#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>  // size_t 정의를 위해 추가
#include <sys/types.h>  // ssize_t 정의를 위해 추가
#include "filesystem.h"

#define MAX_PROCESSES 256
#define STACK_SIZE 1024

typedef enum {
    READY,
    RUNNING,
    WAITING,
    TERMINATED
} ProcessState;

typedef struct Process {
    int pid;
    char name[256];
    ProcessState state;
    int priority;
    int pc; // 프로그램 카운터
    char stack[STACK_SIZE]; // 프로세스 스택
    struct Process *parent; // 부모 프로세스 포인터
    int arrival_time; // 프로세스 도착 시간
    int remaining_time; // 남은 실행 시간
} Process;

extern Process process_table[MAX_PROCESSES];
extern int process_count;

void initialize_process(Process *process, int pid, const char *name);
Process* create_process(const char *name, int priority);
Process* fork_process(Process *parent);
void schedule();
void terminate_process(Process *process);

// 파일 시스템 관련 함수들
int process_open_file(Process *process, const char *path);
int process_close_file(Process *process, int fd);
ssize_t process_read_file(Process *process, const char *path, void *buf, size_t count);
ssize_t process_write_file(Process *process, int fd, const void *buf, size_t count);

#endif // PROCESS_H

