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

    printf("brk on init: %p\n", sbrk(0));

    // local(stack) and global(bss, data, heap) state
    bss_var = 0x13371337;
    int stack_var = 0xcafecafe;
    int *heap_var = (int *)malloc(sizeof(int));
    *heap_var = 0xabcdabcd;
    printf("brk after malloc: %p\n", sbrk(0));

    printf("bss_var....[%p]=0x%08x\n", &bss_var, bss_var);
    printf("data_var...[%p]=0x%08x\n", &data_var, data_var);
    printf("stack_var..[%p]=0x%08x\n", &stack_var, stack_var);
    printf("heap_var...[%p]=0x%08x\n", heap_var, *heap_var);

    // fs state
    int fd = open("README.md", O_RDONLY);
    assert(fd >= 0);
    char buf[20];
    if (read(fd, buf, sizeof(buf)-1) < 0) {
        perror("read error");
    } else {
        buf[sizeof(buf)-1] = '\0';
        printf("%s\n", buf);
    }

    // do snapshot
    int ret = s2e_checkpoint("snapshots/test-ckpt", S2E_SCHED_MUST);
    assert(ret != -1);
    if (ret == 1) {
        printf("continued from snapshot!\n");
    }

    sleep(3);

    // test malloc
    printf("brk after checkpoint: %p\n", sbrk(0));
    int n = 1000000;
    int *p;
    for (volatile int i = 0; i < n; ++i) {
        p = malloc(4);
        // printf("%p\n", p);
        *p = i + 1;
    }
    printf("brk after malloc array: %p\n", sbrk(0));

    if (read(fd, buf, sizeof(buf)-1) < 0) {
        perror("read error");
    } else {
        buf[sizeof(buf)-1] = '\0';
        printf("%s\n", buf);
    }

    data_var = 0xaf7e3;
    printf("bss_var....[%p]=0x%08x\n", &bss_var, bss_var);
    printf("data_var...[%p]=0x%08x\n", &data_var, data_var);
    printf("stack_var..[%p]=0x%08x\n", &stack_var, stack_var);
    printf("heap_var...[%p]=0x%08x\n", heap_var, *heap_var);

    // test: avoid nested checkpoint.
    // ret = s2e_checkpoint("snapshots/test-ckpt", S2E_SCHED_MUST);
    // if (ret < 0) {
    //     perror("checkpoint error");
    // } else if (ret == 1) {
    //     printf("continued from the second checkpoint!\n");
    // }
    // printf("Do something...\n");

    return 0;
}
