#include "sys.h"
#include "config.h"
#include "snap2exe/checkpoint.h"

#include <sys/wait.h>

#include "snap2exe/snap2exe.h"
#include "log.h"
#include "sched.h"
#include "utils.h"

static void once_init();
static void exit_without_side_effects(int status);
static void sync_as_tracee();
static void sync_as_tracer();
static const char *snapshot_default_save_dir();

static int is_snapshot_exe = 0;

/* Return  0 if continued from original processes.
   Return  1 if continued from recovered snapshot executables.
   Return -1 if error. */
int s2e_checkpoint(int cond, const char *save_dir, int policy)
{
    /* Prevent nested snapshots. */
    if (is_snapshot_exe)
        return 0;

    if (!cond)
        return 0;

    if (!save_dir) {
        log_error("Invalid argument: save_dir is NULL");
        return -1;
    }

    once_init();

    if (!is_time_to_snapshot(policy))
        return 0;

    pid_t pid;
    if ((pid = fork()) < 0) {
        log_unix_error("fork snapshoter error");
        return -1;
    }

    if (pid == 0) {
        set_log_identity("snapshoter");

        if ((pid = fork()) < 0) {
            log_unix_error("fork snapshotee error");
            exit_without_side_effects(EXIT_FAILURE);
        }

        if (pid == 0) {
            set_log_identity("snapshotee");
            is_snapshot_exe = 1;
            sync_as_tracee();
            /* Snapshot executables will continue from here. */
            sbrk(1024); /* A trick to avoid crashing caused by malloc. */
            return 1;
        }
        sync_as_tracer(pid);

        if (save_dir == S2E_DEFAULT_SAVE_DIR)
            save_dir = snapshot_default_save_dir();
        if (snap2exe(pid, save_dir) < 0) {
            char buf[MAXLINE];
            log_error("%s", s2e_errmsg(buf, ARRAY_LEN(buf)));
            exit_without_side_effects(EXIT_FAILURE);
        }
        exit_without_side_effects(EXIT_SUCCESS);
    }

    /* Wait child do snapshot. */
    pid_t wait_ret;
    int status;
    do {
        wait_ret = waitpid(pid, &status, 0);
    } while (wait_ret < 0 && errno == EINTR);
    if (wait_ret < 0) {
       log_unix_error("waitpid shouldn't have failed");
       abort();
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
        return -1;
    return 0;
}

static void once_init()
{
    static int done = 0;
    if (done)
        return;
    done = 1;

    /* Locate configure file. */
    const char *home;
    char config_file[MAXPATH];
    if (!(home = getenv("HOME")))
        return;
    snprintf(config_file, ARRAY_LEN(config_file), "%s/.s2econfig", home);

    /* If the configure file doesn't exist, we create a default one. */
    if (access(config_file, F_OK) != 0) {
        save_config(config_file);
        return;
    }

    int ret = load_config(config_file);
    if (ret == -1)
        log_unix_error("load config error");
}

static void exit_without_side_effects(int status)
{
    close_all_fds(NULL);
    _exit(status);
}

static void sync_as_tracee()
{
    if (ptrace_traceme() != 0) {
        log_unix_error("ptrace_traceme error");
        exit_without_side_effects(EXIT_FAILURE);
    }
    raise(SIGSTOP);
}

static void sync_as_tracer(pid_t pid)
{
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        log_unix_error("Fails to wait the tracee to raise SIGTRAP");
        exit_without_side_effects(EXIT_FAILURE);
    }
    if (WIFEXITED(status)) {
        /* The child early exited for some errors. */
        log_warn("Snapshot early exited for some errors.");
        exit_without_side_effects(EXIT_FAILURE);
    }
    if (!WIFSTOPPED(status)) {
        /* The child is killed by some unexpected events. */
        log_error("Got some unexpected events during synchronization.");
        exit_without_side_effects(EXIT_FAILURE);
    }
    /* Set PTRACE_O_EXITKILL so that monitor make child exit by exit itself. */
    if (ptrace_setoptions(pid, PTRACE_O_EXITKILL) != 0) {
        log_unix_error("ptrace_setoptions error");
        exit_without_side_effects(EXIT_FAILURE);
    }
}

static const char *snapshot_default_save_dir()
{
    static char dir[MAXPATH];

    if (dir[0])
        return dir;

    char my_prog_name[MAXPATH];
    memset(my_prog_name, 0, sizeof(my_prog_name));
    if (readlink("/proc/self/exe", my_prog_name, sizeof(my_prog_name)) == -1)
        snprintf(my_prog_name, sizeof(my_prog_name), "unknown");
    my_prog_name[sizeof(my_prog_name) - 1] = '\0';

    const char *home = getenv("HOME");
    if (!home)
        home = "/tmp";

    snprintf(dir, sizeof(dir), "%s/.snapshots/%s", home, my_prog_name);
    return dir;
}
