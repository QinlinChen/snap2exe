#ifndef _SNAP2EXE_CHECKPOINT_H
#define _SNAP2EXE_CHECKPOINT_H

#ifdef __cplusplus
extern "C" {
#endif

#define S2E_SCHED_MUST      0x1
#define S2E_SCHED_PROB      0x2
#define S2E_SCHED_THROTTLE  0x4

#define S2E_DEFAULT_SAVE_DIR ((char *)-1)

/* checkpoint.c */
int s2e_checkpoint(const char *save_dir, int policy);

#ifdef __cplusplus
}
#endif

#endif // _SNAP2EXE_CHECKPOINT_H
