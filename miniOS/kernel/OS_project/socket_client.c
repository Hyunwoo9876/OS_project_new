#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "syscall.h"

int socket_client(int argc, char *argv[]) {
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];

    // 인자가 부족한 경우
    if (argc < 3) {
        fprintf(stderr, "사용법: %s 호스트명 포트\n", argv[0]); // 호스트명과 포트를 제공해야 합니다.
        exit(0);
    }

    portno = atoi(argv[2]); // 포트 번호 설정
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // 소켓 생성
    if (sockfd < 0)
        error("소켓 열기 실패");

    server = gethostbyname(argv[1]); // 호스트 이름으로 서버 정보 가져오기
    if (server == NULL) {
        fprintf(stderr, "에러, 해당 호스트를 찾을 수 없습니다\n");
        exit(0);
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    // 서버에 연결 요청
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("연결 실패");

   
    while (1) { 
    	printf("클라이언트: ");
        bzero(buffer, 256);
        fgets(buffer, 255, stdin); // 사용자 입력 받기
        n = write(sockfd, buffer, strlen(buffer)); // 서버로 메시지 보내기
        if (n < 0)
            error("소켓 쓰기 실패");

        bzero(buffer, 256);
        n = read(sockfd, buffer, 255); // 서버로부터 응답 읽기
        if (n < 0)
            error("소켓 읽기 실패");

        printf("서버: %s", buffer);
        int i = strncmp("Bye", buffer, 3);
        if (i == 0) // "Bye"가 입력되면 연결 종료
            break;
    }

    close(sockfd); // 소켓 닫기
    return 0;
}

