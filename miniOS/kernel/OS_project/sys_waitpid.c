#include <sys/wait.h>

int sys_waitpid(int pid, int *status, int options) {
    return waitpid(pid, status, options);
}
