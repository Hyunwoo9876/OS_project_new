#include <stdlib.h>
#include <stdio.h>
#include "syscall.h"

int Exit(int status) {
    printf("Exiting with status: %d\n", status);
    exit(status);
    return 0;
}
