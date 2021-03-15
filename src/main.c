#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include "snap2exe/snap2exe.h"
#include "error.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
        app_errq("Usage: snap2exe <pid> <save_dir>");

    int pid = atoi(argv[1]);
    const char *save_dir = argv[2];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
        unix_errq("ptrace attach error");

    if (snap2exe(pid, save_dir) < 0) {
        char buf[512];
        app_errq("%s", s2e_errmsg(buf, 512));
    }

    return 0;
}
