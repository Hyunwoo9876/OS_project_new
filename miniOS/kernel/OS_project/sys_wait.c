#include "syscall.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

extern int child_exists;

int Wait() {
    if (!child_exists) {
        fprintf(stderr, "wait failed: No child processes\n");
        return 1;
    }

    int status;
    pid_t pid = wait(&status);
    if (pid == -1) {
        perror("wait failed");
        return 1;
    }
    printf("Child process %d terminated with status %d\n", pid, status);
    child_exists = 0; // 자식 프로세스가 종료되었음을 표시
    return 0;
}
