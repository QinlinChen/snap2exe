#include <stdio.h>
#include <stdlib.h>

#include "snap2exe/checkpoint.h"

int sum(int left, int right)
{
    int sum = 0;
    for (int i = left; i < right; ++i) {
        sum += i;
        if (i == right - 1) // snapshot when i == right - 1.
            s2e_checkpoint("snapshots/test-calc", S2E_SCHED_MUST);
    }
    return sum;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <left> <right>\n", argv[0]);
        return 1;
    }
    int s = sum(atoi(argv[1]), atoi(argv[2]));
    printf("%d\n", s);
    return 0;
}
