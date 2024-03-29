#ifndef _EXE_H
#define _EXE_H

#include <elf.h>

#include "snapshot.h"

#define MAX_SEGMENTS MAX_MEM_MAPS

struct segment {
    Elf64_Phdr phdr;
    char *data;
};

struct exe {
    Elf64_Ehdr ehdr;
    Elf64_Phdr metadata_phdr; /* metadata consist of elf header and program headers. */
    int n_segs;
    struct segment segs[MAX_SEGMENTS];
};

int exe_build_from_snapshot(struct exe *ex, struct snapshot *ss);
void exe_free(struct exe *ex);
int exe_save(int fd, struct exe *ex);

#endif // _EXE_H
