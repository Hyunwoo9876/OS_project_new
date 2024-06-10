#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "system.h"
#include "syscall.h"
#include "filesystem.h"
#include "process.h"

extern Process process_table[MAX_PROCESSES];
extern int process_count;
Process *current_process;

void print_minios(char* str);

void run_test_process() {
    printf("Starting process test...\n");

    // 프로세스 생성 (fork)
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Fork Failed\n");
        return;
    } else if (pid == 0) {
        // 자식 프로세스: 새로운 프로그램 실행 (exec)
        printf("In child process. PID: %d\n", getpid());
        if (execlp("/bin/echo", "echo", "Hello from child process!", NULL) == -1) {
            perror("Exec failed");
        }
        _exit(1);  // Exec 실패 시 자식 프로세스 종료
    } else {
        // 부모 프로세스: 자식 프로세스 기다림 (wait)
        printf("In parent process. PID: %d, Child PID: %d\n", getpid(), pid);
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid failed");
        } else {
            printf("Child process %d terminated with status %d\n", pid, status);
        }
    }

    printf("Process test completed.\n");
}

int main() {
    print_minios("[MiniOS SSU] Hello, World!");

    char *input;
    char server_input[20]; // 서버 주소를 저장할 변수
    char port_input[10];   // 포트 번호를 저장할 변수
    
    while(1) {
        // readline을 사용하여 입력 받기
        input = readline("커맨드를 입력하세요(종료:exit) : ");

        if (strcmp(input,"exit") == 0) {
            break;
        }

        else if (strcmp(input,"minisystem") == 0) {
            minisystem();
        }
        
        //현우
        else if (strcmp(input,"time") ==0) {
            get_time();
        }
        
        else if (strcmp(input,"monitoring_memory") ==0) {
            monitoring_memory();
            return 0;
        }
        
        else if (strcmp(input,"monitoring_cpu") ==0) {
            monitoring_cpu();
            return 0;
        }
        
        //지민
        else if (strcmp(input, "createfile") == 0) {
            char filepath[256];
            printf("Enter filename: ");
            scanf("%s", filepath);
            createfile(filepath);
        }
        else if (strcmp(input, "deletefile") == 0) {
            char filename[256];
            printf("Enter filename: ");
            scanf("%s", filename);
            deletefile(filename);
        }
        else if (strcmp(input, "writefile") == 0) {
            int result = writefile();
            if (result == -1) {
                printf("Write failed.\n");
            }
            else {
                printf("Write successful.\n");
            }
        }
        else if (strcmp(input, "createdir") == 0) {
            char path[256];
            printf("Enter directory path: ");
            scanf("%s", path);
            createdir(path);
        }
        else if (strcmp(input, "deletedir") == 0) {
            char path[256];
            printf("Enter directory path: ");
            scanf("%s", path);
            deletedir(path);
        }
        else if (strcmp(input, "showdir") == 0) {
            print_directory(root, 0);
        }
        else if (strcmp(input, "createprocess") == 0) {
            char name[256];
            int priority;
            printf("Enter process name: ");
            scanf("%s", name);
            printf("Enter process priority: ");
            scanf("%d", &priority);
            Process *new_process = create_process(name, priority);
            if (new_process == NULL) {
                printf("Error creating process '%s'.\n", name);
            } else {
                printf("Process '%s' created with PID %d.\n", name, new_process->pid);
            }
        }
        else if (strcmp(input, "terminateprocess") == 0) {
            int pid;
            printf("Enter process PID: ");
            scanf("%d", &pid);
            int terminated = 0;
            for (int i = 0; i < process_count; i++) {
                if (process_table[i].pid == pid) {
                    terminate_process(&process_table[i]);
                    terminated = 1;
                    break;
                }
            }
            if (!terminated) {
                printf("Error terminating process with PID %d.\n", pid);
            } else {
                printf("Process with PID %d terminated successfully.\n", pid);
            }
        }
        else if (strcmp(input, "schedule") == 0) {
            schedule();
        }
        else if (strcmp(input, "openfile") == 0) {
            char path[256];
            printf("Enter file path: ");
            scanf("%s", path);
            int fd = process_open_file(current_process, path);
            if (fd == -1) {
                printf("Error opening file '%s'.\n", path);
            } else {
                printf("File '%s' opened with file descriptor %d.\n", path, fd);
            }
        }
        else if (strcmp(input, "closefile") == 0) {
            int fd;
            printf("Enter file descriptor: ");
            scanf("%d", &fd);
            if (process_close_file(current_process, fd) == -1) {
                printf("Error closing file descriptor %d.\n", fd);
            } else {
                printf("File descriptor %d closed successfully.\n", fd);
            }
        }
        else if (strcmp(input, "readfile") == 0) {
            char path[256];
            printf("Enter file path: ");
            scanf("%s", path);
            char buf[256];
            ssize_t bytes_read = process_read_file(current_process, path, buf, sizeof(buf) - 1);
            if (bytes_read == -1) {
                printf("Error reading file '%s'.\n", path);
            } else {
                buf[bytes_read] = '\0';
                printf("Read %zd bytes: %s\n", bytes_read, buf);
            }
        }
        else if (strcmp(input, "writefilefd") == 0) {
            int fd;
            printf("Enter file descriptor: ");
            scanf("%d", &fd);
            char buf[256];
            printf("Enter content to write (max 255 characters): ");
            scanf(" %[^\n]", buf);
            ssize_t bytes_written = process_write_file(current_process, fd, buf, strlen(buf));
            if (bytes_written == -1) {
                printf("Error writing to file descriptor %d.\n", fd);
            } else {
                printf("Written %zd bytes to file descriptor %d.\n", bytes_written, fd);
            }
        }
        
        //인아
        else if (strcmp(input, "IPC_write") == 0) {
            IPC_W();
        }
        
        else if (strcmp(input, "IPC_read") == 0) {
            IPC_R();
        }
        
        else if (strcmp(input,"Server") == 0){
            printf("어떤 포트 번호를 사용할까요? ");
            fgets(port_input, sizeof(port_input), stdin);
            port_input[strlen(port_input) - 1] = '\0'; 
            char *argv[] = {"Server", port_input}; 
            socket_server(2, argv);
            printf("서버를 생성했어요. Clinet를 기다립니다.");
        } 
        
        else if (strcmp(input,"Client") == 0){
            printf("어떤 서버 IP 주소를 사용할까요? ");
            fgets(server_input, sizeof(server_input), stdin);
            server_input[strlen(server_input) - 1] = '\0'; 
            printf("어떤 포트 번호를 사용할까요? ");
            fgets(port_input, sizeof(port_input), stdin);
            port_input[strlen(port_input) - 1] = '\0'; 
            char *client_argv[] = {"Client", server_input, port_input}; 
            socket_client(3, client_argv);
            printf("서버에 들어왔어요.");
        } 
        
        //준영
        else if (strcmp(input, "fork") == 0) {
            Fork();
        }
        
        else if (strcmp(input, "exec") == 0) {
            Exec();
        } 
        
        else if (strcmp(input, "abort") == 0) {
            Abort();
        }
        
        else if (strcmp(input, "exit_program") == 0) {
            int status;
            printf("Enter exit status: ");
            scanf("%d", &status);
            Exit(status);
        }
        
        else if (strcmp(input, "wait_time") == 0) {
            int seconds;
            printf("Enter wait time in seconds: ");
            scanf("%d", &seconds);
            wait_time(seconds);  
        }
        
        else if (strcmp(input, "wait_event") == 0) {
            wait_for_event();
        }
        
        else if (strcmp(input, "signal_event") == 0) {
            signal_event();
        }
        
        else if (strcmp(input, "kill") == 0) {
            pid_t pid;
            int sig;
            printf("Enter PID: ");
            scanf("%d", &pid);
            printf("Enter signal: ");
            scanf("%d", &sig);
            Kill(pid, sig);
        }
        
        else if (strcmp(input, "getpid") == 0) {
            GetPID();
        }
        
        else if (strcmp(input, "getppid") == 0) {
            GetPPID();
        }
        
        else if (strcmp(input, "wait") == 0) {
            Wait();
        }
        
        else if (strcmp(input, "test_process") == 0) {
            run_test_process();
        }

        else system(input);
}

    // 메모리 해제
    free(input);
    print_minios("[MiniOS SSU] MiniOS Shutdown........");

    return(1);
}

void print_minios(char* str) {
        printf("%s\n",str);
}
