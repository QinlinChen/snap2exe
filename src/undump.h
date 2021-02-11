#ifndef __UNDUMP_H__
#define __UNDUMP_H__

#include <elf.h>
#include "core.h"

typedef struct {
    Elf64_Phdr phdr;
    char *segment;
} undump_segment;

typedef struct {
    Elf64_Ehdr ehdr;
    Elf64_Phdr metadata_phdr;
    int n_segs;
    undump_segment *segments;
} undumped_program;

/* Methods to manipulate the undumped_program struct */

undumped_program *new_undumped_program();
undumped_program *undump(struct core *c);
int write_undumped(int fd, undumped_program *p);

#endif