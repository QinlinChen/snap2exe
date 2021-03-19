#include "sys.h"
#include "config.h"
#include "snap2exe/snap2exe.h"

#include <time.h>

#include "snapshot.h"
#include "exe.h"
#include "utils.h"

int snap2exe(int pid, const char *save_dir)
{
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

    struct snapshot ss;
    if (snapshot_build(&ss, pid) < 0)
        return -1;

    if (snapshot_dump_opened_files(&ss, snapshot_dir) < 0)
        return -1;

    struct exe ex;
    if (exe_build_from_snapshot(&ex, &ss) < 0)
        return -1;

    char exec_path[MAXPATH];
    snprintf(exec_path, ARRAY_LEN(exec_path), "%s/cont", snapshot_dir);
    int fd = open(exec_path, O_CREAT|O_RDWR, 0700);
    if (fd < 0) {
        s2e_unix_err("fail to open new exec: %s", exec_path);
        goto errout;
    }
    if (exe_save(fd, &ex) < 0)
        goto errout;

    exe_free(&ex);
    close(fd);
    return 0;

errout:
    close(fd);
    exe_free(&ex);
    return -1;
}
