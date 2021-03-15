#ifndef _SNAPSHOT_H
#define _SNAPSHOT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>

#include "macros.h"

struct mem_map {
    void *start;
    void *end;
    int prot;
};

struct fdinfo {
    int fd;
    struct stat statbuf;
    off_t offset;
};

#define MAX_MEM_MAPS    50
#define MAX_FDINFO      256

struct snapshot {
    pid_t pid;
    struct user_regs_struct regs;
    int n_maps;
    struct mem_map maps[MAX_MEM_MAPS];
    int n_fds;
    struct fdinfo fdinfo[MAX_FDINFO];
};

int snapshot_build(struct snapshot *ss, pid_t pid);
void snapshot_show(struct snapshot *ss);

char *dump_mem_map(pid_t pid, struct mem_map *map);

#endif // _SNAPSHOT_H
