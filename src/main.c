#include "sys.h"
#include "snap2exe.h"
#include "utils.h"
#include "error.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
        app_errq("Usage: snap2exe <pid> <new-exec>");

    int pid = atoi(argv[1]);
    const char *new_exec = argv[2];

    if (ptrace_attach(pid) != 0)
        unix_errq("ptrace attach error");

    snap2exe(pid, new_exec);
    return 0;
}
