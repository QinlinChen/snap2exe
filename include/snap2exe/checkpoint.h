#ifndef _SNAP2EXE_CHECKPOINT_H
#define _SNAP2EXE_CHECKPOINT_H

#ifdef __cplusplus
#define extern "C" {
#endif

/* checkpoint.c */
int checkpoint(int cond, const char *save_dir);

#ifdef __cplusplus
}
#endif

#endif // _SNAP2EXE_CHECKPOINT_H