#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define SHM_NAME "/project"
#define MAX_MESSAGE_SIZE 256

int IPC_R(void)
{
    // 공유 메모리 열기
    int shmd = shm_open(SHM_NAME, O_RDWR, 0600);
    if (shmd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    // 공유 메모리 크기 설정
    int size = MAX_MESSAGE_SIZE;
    char *data = (char *)mmap(NULL, size, PROT_READ, MAP_SHARED, shmd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(shmd);
        exit(EXIT_FAILURE);
    }

    // 공유 메모리에서 문자열 읽기
    printf("공유 메모리에 저장된 데이터: %s\n", data);

    // 매핑 해제 및 공유 메모리 닫기
    if (munmap(data, size) == -1) {
        perror("munmap");
        close(shmd);
        exit(EXIT_FAILURE);
    }

    close(shmd);

    return 0;
}


