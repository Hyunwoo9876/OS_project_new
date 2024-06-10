#include <stdio.h>
#include <unistd.h>
#include "system.h"

int Exec() {
    printf("Running exec...\n");
    execlp("/bin/ls", "ls", NULL);
    return 0;
}
