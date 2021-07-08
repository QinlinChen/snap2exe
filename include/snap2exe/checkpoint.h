#ifndef _SNAP2EXE_CHECKPOINT_H
#define _SNAP2EXE_CHECKPOINT_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    S2E_SCHED_MUST,
    S2E_SCHED_PROB,
};

/* checkpoint.c */
int s2e_checkpoint(int cond, const char *save_dir, int policy);

#ifdef __cplusplus
}
#endif

#endif // _SNAP2EXE_CHECKPOINT_H
