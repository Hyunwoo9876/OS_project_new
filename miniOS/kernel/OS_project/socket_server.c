#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void socket_server(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "포트 번호가 제공되지 않았습니다. 프로그램을 종료합니다.\n");
        exit(1);
    }

    int sockfd, newsockfd, portno, n;
    char buffer[255];
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("소켓 열기 실패.");
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("바인딩 실패.");
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0) {
        error("연결 수락 실패.");
    }

    while (1) {
   
        bzero(buffer, 255);
        n = read(newsockfd, buffer, 255);
        if (n < 0) {
            error("소켓 읽기 실패.");
        }
        printf("클라이언트: %s", buffer);
 
        printf("서버: "); // 서버가 메시지를 보낼 때에는 "서버: "를 출력합니다.
        bzero(buffer, 255);
        fgets(buffer, 255, stdin);

        n = write(newsockfd, buffer, strlen(buffer));
        if (n < 0) {
            error("소켓 쓰기 실패.");
        }

        int i = strncmp("Bye", buffer, 3);
        if (i == 0)
            break;
    }

    close(newsockfd);
    close(sockfd);
}

