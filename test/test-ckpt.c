#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <assert.h>

#include "snap2exe/checkpoint.h"

static int bss_var;
static int data_var = 0xbef03e; //before

void bye() {
    printf("Bye!\n");
}

int main()
{
    atexit(bye);

    bss_var = 0x13371337;
    int stack_var = 0xcafecafe;
    int *heap_var = (int *)malloc(sizeof(int));
    *heap_var = 0xabcdabcd;

    printf("bss_var....[%p]=0x%08x\n", &bss_var, bss_var);
    printf("data_var...[%p]=0x%08x\n", &data_var, data_var);
    printf("stack_var..[%p]=0x%08x\n", &stack_var, stack_var);
    printf("heap_var...[%p]=0x%08x\n", heap_var, *heap_var);

    int fd = open("Makefile", O_RDONLY);
    assert(fd >= 0);
    
    char buf[512];
     if (read(fd, buf, 20) < 0) {
        perror("read error");
    } else {
        buf[19] = '\0';
        printf("%s\n", buf);
    }

    int ret = checkpoint(1, "snapshots-test-ckpt");
    printf("checkpoint ret: %d\n", ret);
    if (ret) {
        printf("continued from snapshot!\n");
    }

    if (read(fd, buf, 20) < 0) {
        perror("read error");
    } else {
        buf[19] = '\0';
        printf("%s\n", buf);
    }

    data_var = 0xaf7e3; //after
    printf("bss_var....[%p]=0x%08x\n", &bss_var, bss_var);
    printf("data_var...[%p]=0x%08x\n", &data_var, data_var);
    printf("stack_var..[%p]=0x%08x\n", &stack_var, stack_var);
    printf("heap_var...[%p]=0x%08x\n", heap_var, *heap_var);

    return 0;
}
