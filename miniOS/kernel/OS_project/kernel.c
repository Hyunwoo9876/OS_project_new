#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "filesystem.h"
#include "process.h"
#include "round_robin.h"
#include "createfile.h"
#include "deletefile.h"
#include "writefile.h"
#include "createdir.h"
#include "deletedir.h"

extern Process process_table[MAX_PROCESSES];
extern int process_count;

Process *current_process;

void print_minios(char* str);
void ipc_example();
void *monte_carlo(void *arg);
void compute_pi();
void minisystem();

int main() {
    print_minios("[MiniOS SSU] Hello, World!");

    initialize_file_system();

    current_process = create_process("init", 0);

    char *input;

    while (1) {
        input = readline("커맨드를 입력하세요(종료:exit) : ");

        if (strcmp(input, "exit") == 0) {
            break;
        }

        if (strcmp(input, "minisystem") == 0) {
            minisystem();
        }
        else if (strcmp(input, "fork") == 0) {
            Process *new_process = fork_process(current_process);
            if (new_process == NULL) {
                printf("Error forking process.\n");
            } else {
                printf("Process forked with PID %d.\n", new_process->pid);
            }
        }
        else if (strcmp(input, "ipc") == 0) {
            ipc_example();
        }
        else if (strcmp(input, "pi") == 0) {
            compute_pi();
        }
        else if (strcmp(input, "round_robin") == 0) {
            Process processes[] = {
                {1, "P1", READY, 10, 0, {0}, NULL, 0, 10},
                {2, "P2", READY, 5, 0, {0}, NULL, 1, 5},
                {3, "P3", READY, 8, 0, {0}, NULL, 2, 8},
                {4, "P4", READY, 3, 0, {0}, NULL, 3, 3},
                {5, "P5", READY, 6, 0, {0}, NULL, 4, 6},
                {6, "P6", READY, 7, 0, {0}, NULL, 5, 7},
                {7, "P7", READY, 4, 0, {0}, NULL, 6, 4},
                {8, "P8", READY, 9, 0, {0}, NULL, 7, 9}
            };
            int n = sizeof(processes) / sizeof(processes[0]);
            int quantum = 3;

            round_robin(processes, n, quantum);
        }
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
        else {
            system(input);
        }

        free(input);
    }

    print_minios("[MiniOS SSU] MiniOS Shutdown........");

    return 1;
}

void print_minios(char* str) {
    printf("%s\n", str);
}

