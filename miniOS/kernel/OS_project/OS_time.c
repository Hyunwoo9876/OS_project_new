#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

// 현재 시간을 반환하는 함수
void get_time() {
    struct timeval tv;
    struct timezone tz;
    struct tm *tm_info;

    if (gettimeofday(&tv, &tz) == -1) {
        perror("gettimeofday");
        return;
    }

    time_t current_time = tv.tv_sec;
    tm_info = localtime(&current_time);

    printf("Current time: %02d:%02d:%02d\n", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

// 지정된 시간으로 시스템 시간을 설정하는 함수
int set_time(int hours, int minutes, int seconds) {
    struct timeval tv;
    struct timezone tz;
    struct tm new_time;

    if (gettimeofday(&tv, &tz) == -1) {
        perror("gettimeofday");
        return errno;
    }

    time_t current_time = tv.tv_sec;
    new_time = *localtime(&current_time);

    new_time.tm_hour = hours;
    new_time.tm_min = minutes;
    new_time.tm_sec = seconds;

    tv.tv_sec = mktime(&new_time);
    tv.tv_usec = 0;

    if (settimeofday(&tv, &tz) == -1) {
        perror("settimeofday");
        return errno;
    }

    return 0;
}

