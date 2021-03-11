#ifndef _SNAPSHOT_H
#define _SNAPSHOT_H

#include <sys/types.h>
#include <sys/user.h>

#define MAX_PROC_MAPS 50

struct proc_map {
    void *start;
    void *end;
    int prot;
};

struct snapshot {
    pid_t pid;
    struct user_regs_struct regs;
    int n_maps;
    struct proc_map maps[MAX_PROC_MAPS];
};

int build_snapshot(struct snapshot *ss, pid_t pid);
void show_snapshot(struct snapshot *ss);

char *alloc_read_proc_map(pid_t pid, struct proc_map *map);

#endif // _SNAPSHOT_H