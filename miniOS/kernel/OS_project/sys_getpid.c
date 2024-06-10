#include <stdio.h>
#include <unistd.h>
#include "syscall.h"

int GetPID() {
    pid_t pid = getpid();
    printf("Current process ID: %d\n", pid);
    return pid;
}
