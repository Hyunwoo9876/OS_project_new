#include "syscall.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

// 전역 변수 선언
int child_exists = 0;

int Fork() {
    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "Fork Failed\n");
        return 1;
    } else if (pid == 0) {
        // 자식 프로세스 코드
        printf("In child process. PID: %d\n", getpid());
        if (execlp("/bin/echo", "echo", "Hello from child process!", NULL) == -1) {
            perror("Exec failed");
        }
        _exit(1);  // Exec 실패 시 자식 프로세스 종료
    } else {
        // 부모 프로세스 코드
        child_exists = 1; // 자식 프로세스가 생성되었음을 표시
    }

    return 0;
}
