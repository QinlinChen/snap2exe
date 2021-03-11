#ifndef _SNAP2EXE_H
#define _SNAP2EXE_H

#include <sys/types.h>

int checkpoint(int cond);
int snap2exe(pid_t pid, const char *new_exec);

#endif // _SNAP2EXE_H