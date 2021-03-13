#include "sys.h"
#include "snap2exe/snap2exe.h"

#include "snapshot.h"
#include "exe.h"

int snap2exe(int pid, const char *new_exec)
{
    struct snapshot ss;
    struct exe ex;

    if (snapshot_build(&ss, pid) < 0)
        return -1;

    // snapshot_show(&ss);

    int fd = open(new_exec, O_CREAT|O_RDWR, 0700);
    if (fd < 0) {
        s2e_unix_err("fail to open new exec: %s", new_exec);
        return -1;
    }

    if (exe_build_from_snapshot(&ex, &ss) < 0)
        return -1;

    int ret = exe_save(fd, &ex);
    exe_free(&ex);
    close(fd);
    return ret;
}
