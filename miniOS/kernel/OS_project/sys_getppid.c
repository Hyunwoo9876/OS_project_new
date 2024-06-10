#include <stdio.h>
#include <unistd.h>
#include "syscall.h"

int GetPPID() {
    pid_t ppid = getppid();
    printf("Parent process ID: %d\n", ppid);
    return ppid;
}
