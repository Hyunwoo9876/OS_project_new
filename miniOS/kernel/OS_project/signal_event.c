#include "event_control.h"
#include <stdio.h>
#include <pthread.h>

extern pthread_cond_t cond;
extern pthread_mutex_t mutex;

void signal_event() {
    pthread_mutex_lock(&mutex);  // 뮤텍스로 보호
    printf("Signaling event...\n");
    pthread_cond_signal(&cond);  // 대기 중인 스레드에게 신호
    pthread_mutex_unlock(&mutex);  // 뮤텍스 잠금 해제
}
