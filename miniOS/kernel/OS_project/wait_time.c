#include <unistd.h>
#include "system.h"
#include <stdio.h>

int wait_time(int seconds) {
    printf("Waiting for %d seconds...\n", seconds);
    sleep(seconds);
    printf("Wait time of %d seconds completed.\n", seconds);
    return 0;
}
