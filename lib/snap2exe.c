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

    // snapshot_dir should be unique between different calls.
    char snapshot_dir[MAXPATH];
    if (snprintf(snapshot_dir, ARRAY_LEN(snapshot_dir), "%s/%ld-%ld",
                 save_dir, (long)time(NULL), (long)getpid()) >= ARRAY_LEN(snapshot_dir)) {
        s2e_unix_err("exceed max path length");
        return -1;
    }
    if (mkdir(snapshot_dir, 0777) < 0) {
        s2e_unix_err("mkdir '%s' error", snapshot_dir);
        return -1;
    }

    struct snapshot ss;
    if (snapshot_build(&ss, snapshot_dir, pid) < 0)
        return -1;
    // snapshot_show(&ss);
    if (snapshot_dump(&ss) < 0)
        return -1;

    struct exe ex;
    if (exe_build_from_snapshot(&ex, &ss) < 0)
        return -1;

    char exec_path[MAXPATH];
    if (snprintf(exec_path, ARRAY_LEN(exec_path), "%s/cont",
                 snapshot_dir)>= ARRAY_LEN(snapshot_dir)) {
        s2e_unix_err("exceed max path length: '%s/cont'", snapshot_dir);
        return -1;
    }
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
