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

struct fdstat {
    int fd;
    struct stat filestat;
    off_t offset;
    int oflag;
};

#define MAX_MEM_MAPS    50
#define MAX_FDSTAT      256

struct snapshot {
    pid_t pid;
    struct user_regs_struct regs;
    int n_maps;
    struct mem_map maps[MAX_MEM_MAPS];
    int n_fds;
    struct fdstat fdstat[MAX_FDSTAT];
};

int snapshot_build(struct snapshot *ss, pid_t pid);
void snapshot_show(struct snapshot *ss);
int snapshot_dump_opened_files(struct snapshot *ss, const char *dump_dir);
char *fetch_mem_map(pid_t pid, struct mem_map *map);

#endif // _SNAPSHOT_H
