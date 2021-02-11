#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int is_snapshot = 0;

int main()
{
    printf("%p\n", &errno);
    is_snapshot = 1;
    sleep(10);

    printf("Snapshot\n");
    return 0;
}
