#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "syscall.h"

int Kill(pid_t pid, int sig) {
    if (kill(pid, sig) == -1) {
        perror("kill failed");
        return 1;
    }
    printf("Signal %d sent to process %d\n", sig, pid);
    return 0;
}
