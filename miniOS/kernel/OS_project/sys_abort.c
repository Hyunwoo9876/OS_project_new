#include <stdlib.h>
#include <stdio.h>
#include "system.h"

int Abort() {
    printf("Process aborted\n");
    abort();
    return 0;
}
