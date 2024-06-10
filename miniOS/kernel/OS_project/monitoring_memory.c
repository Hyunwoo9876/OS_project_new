#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>
#include "syscall.h"

void print_memory_usage(WINDOW *win);

void monitoring_memory() {
    initscr();            // ncurses 초기화
    noecho();             // 입력된 문자를 화면에 출력하지 않음
    curs_set(FALSE);      // 커서 숨기기

    WINDOW *win = newwin(10, 50, 1, 1); // 새로운 창 생성 (행, 열, y좌표, x좌표)

    while (1) {
        werase(win);      // 창 지우기
        box(win, 0, 0);   // 창에 테두리 그리기
        print_memory_usage(win); // 메모리 사용량 출력
        wrefresh(win);    // 창 업데이트
        sleep(1);         // 1초 대기
    }

    delwin(win);          // 창 삭제
    endwin();             // ncurses 종료
}

void print_memory_usage(WINDOW *win) {
    FILE *file = fopen("/proc/meminfo", "r");
    if (file == NULL) {
        mvwprintw(win, 1, 1, "Failed to open /proc/meminfo");
        return;
    }

    char line[256];
    unsigned long total_memory = 0;
    unsigned long free_memory = 0;
    unsigned long available_memory = 0;
    unsigned long buffers = 0;
    unsigned long cached = 0;

    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "MemTotal: %lu kB", &total_memory) == 1) {
            continue;
        }
        if (sscanf(line, "MemFree: %lu kB", &free_memory) == 1) {
            continue;
        }
        if (sscanf(line, "MemAvailable: %lu kB", &available_memory) == 1) {
            continue;
        }
        if (sscanf(line, "Buffers: %lu kB", &buffers) == 1) {
            continue;
        }
        if (sscanf(line, "Cached: %lu kB", &cached) == 1) {
            continue;
        }
    }
    fclose(file);

    mvwprintw(win, 1, 1, "Total Memory: %lu kB", total_memory);
    mvwprintw(win, 2, 1, "Free Memory: %lu kB", free_memory);
    mvwprintw(win, 3, 1, "Available Memory: %lu kB", available_memory);
    mvwprintw(win, 4, 1, "Buffers: %lu kB", buffers);
    mvwprintw(win, 5, 1, "Cached: %lu kB", cached);
}
