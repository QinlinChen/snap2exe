#include "sys.h"
#include "snap2exe/checkpoint.h"

#include <sys/wait.h>

#include "snap2exe/snap2exe.h"
#include "utils.h"

static void exit_without_side_effects(int status);
static void sync_as_tracee();
static void sync_as_tracer();

/* Return  0 if continued from original processes.
   Return  1 if continued from recovered snapshot executables.
   Return -1 if error. */
int checkpoint(int cond)
{
    // TODO: improve error reporting.
    if (!cond)
        return 0;

    pid_t pid;
    if ((pid = fork()) < 0)
       return -1;

    if (pid == 0) {
        if ((pid = fork()) < 0)
            exit_without_side_effects(EXIT_FAILURE);

        if (pid == 0) {
            sync_as_tracee();
            return 1; /* Recovered executables will continue from here. */
        }
        sync_as_tracer(pid);

        if (snap2exe(pid, "cont") < 0) {
            perror("snap2exe error");
            exit_without_side_effects(EXIT_SUCCESS);
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
       perror("waitpid shouldn't have failed");
       abort();
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
        return -1;
    return 0;
}

static void exit_without_side_effects(int status)
{
    close_all_fds(NULL);
    _exit(status);
}

static void sync_as_tracee()
{
    if (ptrace_traceme() != 0) {
        perror("ptrace_traceme error");
        exit_without_side_effects(EXIT_FAILURE);
    }
    raise(SIGSTOP);
}

static void sync_as_tracer(pid_t pid)
{
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("Fails to wait the tracee to raise SIGTRAP");
        exit_without_side_effects(EXIT_FAILURE);
    }
    if (WIFEXITED(status)) {
        /* The child early exited for some errors. */
        perror("Snapshot early exited for some errors.");
        exit_without_side_effects(EXIT_FAILURE);
    }
    if (!WIFSTOPPED(status)) {
        /* The child is killed by some unexpected events. */
        perror("Got some unexpected events during synchronization.");
        exit_without_side_effects(EXIT_FAILURE);
    }
    /* Set PTRACE_O_EXITKILL so that monitor make child exit by exit itself. */
    if (ptrace_setoptions(pid, PTRACE_O_EXITKILL) != 0) {
        perror("ptrace_setoptions error");
        exit_without_side_effects(EXIT_FAILURE);
    }
}
