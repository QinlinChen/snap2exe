#include "sys.h"
#include "snap2exe/snap2exe.h"

#include <time.h>

#include "snapshot.h"
#include "exe.h"
#include "macros.h"
#include "utils.h"

int snap2exe(int pid, const char *save_dir)
{
    struct snapshot ss;
    struct exe ex;

    if (snapshot_build(&ss, pid) < 0)
        return -1;

    // snapshot_show(&ss);

    if (mkdir_p(save_dir, 0777) < 0) {
        s2e_unix_err("mkdir '%s' error", save_dir);
        return -1;
    }

    // TODO: make snapshot_dir unique between different calls.
    char snapshot_dir[MAXPATH];
    snprintf(snapshot_dir, ARRAY_LEN(snapshot_dir), "%s/%ld",
             save_dir, (long)time(NULL));
    if (mkdir(snapshot_dir, 0777) < 0) {
        s2e_unix_err("mkdir '%s' error", snapshot_dir);
        return -1;
    }

    char new_exec[MAXPATH];
    snprintf(new_exec, ARRAY_LEN(new_exec), "%s/cont", snapshot_dir);
    int fd = open(new_exec, O_CREAT|O_RDWR, 0700);
    if (fd < 0) {
        s2e_unix_err("fail to open new exec: %s", new_exec);
        return -1;
    }

    if (exe_build_from_snapshot(&ex, &ss) < 0) {
        close(fd);
        return -1;
    }

    int ret = exe_save(fd, &ex);
    exe_free(&ex);
    close(fd);
    return ret;
}
