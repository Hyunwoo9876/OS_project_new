#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/time.h>
#include <pthread.h>

// 조건 변수와 뮤텍스 선언
extern pthread_cond_t cond;
extern pthread_mutex_t mutex;

//현우
void get_time();
int set_time(int hours, int miniutes, int seconds);
void monitoring_memory();
void monitoring_cpu();

//지민
void createdir(const char *path);
int createfile(const char *filepath);
int deletedir(const char *dirpath);
int deletefile(const char *filename);
int writefile();  

//인아
int IPC_W();
int IPC_R();
void socket_server();
int socket_client();
void error(const char *msg);

//준영
int Fork();
int Exec();
int Abort();
int Exit(int status);
int wait_time(int seconds);
void wait_for_event();
void signal_event();
int Kill(pid_t pid, int sig);
int Exit(int status);
int GetPID();
int GetPPID();
int Wait();

#endif
