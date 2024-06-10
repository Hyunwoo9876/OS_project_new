#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define SHM_NAME "/project"
#define MAX_MESSAGE_SIZE 256

int IPC_W(void)
{
    // 사용자로부터 메시지 입력받기
    char input_message[MAX_MESSAGE_SIZE];
    printf("저장할 메시지를 입력하세요: ");
    fgets(input_message, MAX_MESSAGE_SIZE, stdin);
    input_message[strcspn(input_message, "\n")] = '\0';  // 개행 문자 제거

    int shmd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0600);
    if (shmd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    int size = strlen(input_message) + 1;  // 널 종결 문자를 위한 +1
    if (ftruncate(shmd, size) == -1) {
        perror("ftruncate");
        close(shmd);
        exit(EXIT_FAILURE);
    }

    char *data = (char *)mmap(NULL, size, PROT_WRITE, MAP_SHARED, shmd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(shmd);
        exit(EXIT_FAILURE);
    }

    strcpy(data, input_message);  // 메시지를 공유 메모리에 복사

    printf("공유 메모리에 저장됨: %s\n", input_message);

    if (munmap(data, size) == -1) {
        perror("munmap");
        close(shmd);
        exit(EXIT_FAILURE);
    }

    close(shmd);

    return 0;
}

