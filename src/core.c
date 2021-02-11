#include "core.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "elfcommon.h"

static void check_core(struct core *c);
static void parse_core_note(struct core *c);
static Elf64_Phdr *find_note_segment(struct core *c);
static Elf64_Nhdr *find_prstatus_note(char *note_beg, char *note_end, long align);

struct core *load_core(const char *filename)
{
    struct core *c = (struct core *)malloc(sizeof(struct core));
    if (!c)
        return NULL;

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        goto errout_free_mem;
    
    struct stat sbuf;
    if (fstat(fd, &sbuf) < 0)
        goto errout_close_fd;
    
    char *data = (char *)mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
        goto errout_close_fd;

    c->fd = fd;
    c->size = sbuf.st_size;
    c->data = data;

    check_core(c);
    parse_core_note(c);

    return c;

errout_close_fd:
    close(fd);
errout_free_mem:
    free(c);
    return NULL;
}

static void check_core(struct core *c)
{
    char *e_ident = c->data;
    if (strncmp(e_ident, ELFMAG, SELFMAG))
        app_errq("Input file is not an ELF file!");
    if (e_ident[EI_CLASS] != ELFCLASS64)
        app_errq("This version supports only 64 bit core dumps!");
    if (e_ident[EI_DATA] != ELFDATA2LSB)
        app_errq("This version supports only Little Endian!");

    Elf64_Ehdr *ehdr = elf_get_elf_header(c->data);
    if (ehdr->e_type != ET_CORE)
        app_errq("Input file is not a core dump!");
    if (ehdr->e_machine != EM_X86_64)
        app_errq("This version supports only the x86-64 machine!");
}

#define NH_ALIGN_SIZE(sz, align)  (((sz) + ((align) - 1)) & ~((align) - 1))
#define NH_DATA(nh)         ((char *)(nh) + sizeof(*(nh)))
#define NH_NAME(nh)         NH_DATA(nh)
#define NH_DESC(nh, align)  (NH_DATA(nh) + NH_ALIGN_SIZE((nh)->n_namesz, align))
#define NH_NEXT(nh, align)  ((Elf64_Nhdr *)(NH_DESC(nh, align) + NH_ALIGN_SIZE((nh)->n_descsz, align)))

static void parse_core_note(struct core *c)
{
    Elf64_Phdr *note_phdr = find_note_segment(c);
    if (!note_phdr)
        app_errq("Invalid core dump: the NOTE segment doesn't exist.");

    long align = note_phdr->p_align;
    if (align < 4)
        align = 4;
    else if (align != 4 && align != 8)
        app_errq("Corrupt note: alignment %ld, expecting 4 or 8.", align);

    char *note_beg = c->data + note_phdr->p_offset;
    char *note_end = note_beg + note_phdr->p_filesz;
    Elf64_Nhdr *nh = find_prstatus_note(note_beg, note_end, align);
    if (!nh)
        app_errq("Invalid core dump: cannot find prstatus.");
    if (strcmp(NH_NAME(nh), "CORE") != 0)
        app_errq("Invalid note: expect CORE for prstatus, but get %s.", NH_NAME(nh));
    if (nh->n_descsz != sizeof(prstatus))
        app_errq("Invalid note: unexpected desc size %ld for prstatus.", nh->n_descsz);

    c->status = (prstatus *)NH_DESC(nh, align);
}

static Elf64_Phdr *find_note_segment(struct core *c)
{
    Elf64_Ehdr *ehdr = elf_get_elf_header(c->data);
    Elf64_Phdr *phdr = elf_get_program_headers(c->data);
    for (int i = 0; i < ehdr->e_phnum; ++i, ++phdr)
        if (phdr->p_type == PT_NOTE)
            return phdr;
    return NULL;
}

static Elf64_Nhdr *find_prstatus_note(char *note_beg, char *note_end, long align)
{
    Elf64_Nhdr *nh = (Elf64_Nhdr *)note_beg;
    while ((char *)nh < note_end) {
        if (nh->n_type == NT_PRSTATUS)
            return nh;
        nh = NH_NEXT(nh, align);
    }
    return NULL;
}

void show_core_data(struct core *c)
{
    Elf64_Ehdr *ehdr = elf_get_elf_header(c->data);

    printf("Core: %p\n", c);
    printf("ELF Type: %d\n", ehdr->e_type);
    printf("ELF Id: %c%c%c%c\n", ehdr->e_ident[0], ehdr->e_ident[1],
           ehdr->e_ident[2], ehdr->e_ident[3]);

    prstatus *pr = c->status;
    printf("Program Status: pid = %d, ppid = %d, pgrp = %d, sid = %d\n\n",
           pr->pr_pid, pr->pr_ppid, pr->pr_pgrp, pr->pr_sid);

    regs *r = &pr->pr_reg;
    printf("rax: 0x%lx, rbx: 0x%lx, rcx: 0x%lx, rdx: 0x%lx\n",
           r->rax, r->rbx, r->rcx, r->rdx);
    printf("rsi: 0x%lx, rdi: 0x%lx, rbp: 0x%lx, rsp: 0x%lx\n",
           r->rsi, r->rdi, r->rbp, r->rsp);
    printf("r8: 0x%lx, r9: 0x%lx, r10: 0x%lx, r11: 0x%lx\n",
           r->r8, r->r9, r->r10, r->r11);
    printf("r12: 0x%lx, r13: 0x%lx, r14: 0x%lx, r15: 0x%lx\n",
           r->r12, r->r13, r->r14, r->r15);
    printf("rip: 0x%lx, eflags: 0x%lx\n", r->rip, r->eflags);
    printf("fs.base: 0x%lx, gs.base: 0x%lx\n", r->fs_base, r->gs_base);
    printf("cs: 0x%lx, ss: 0x%lx, ds: 0x%lx, es: 0x%lx, fs: 0x%lx, gs: 0x%lx\n",
           r->cs, r->ss, r->ds, r->es, r->fs, r->gs);

    printf("\nProgram Headers: %d\n", ehdr->e_phnum);
    Elf64_Phdr *ph = elf_get_program_headers(c->data);
    for (int i = 0; i < ehdr->e_phnum; i++, ph++) {
        printf("\tProgram Header: Type: 0x%x Off: 0x%lx Allign: 0x%lx VAddr: 0x%lx FSize:0x%lx MemSize: 0x%lx\n",
               ph->p_type, ph->p_offset, ph->p_align, ph->p_vaddr, ph->p_filesz, ph->p_memsz);
    }

    printf("\nSections: %d\n", ehdr->e_shnum);
    Elf64_Shdr *s = elf_get_section_headers(c->data);
    for (int i = 0; i < ehdr->e_shnum; i++, s++) {
        printf("\tSection: Name \"%s\"\n", elf_get_section_name(c->data, s));
    }
}

uintptr_t find_core_entry_point(struct core *c)
{
    Elf64_Ehdr *c_ehdr = elf_get_elf_header(c->data);
    Elf64_Phdr *c_phdrs = elf_get_program_headers(c->data);

    /* Print all core dump segments */
    printf("\n[*] Core dump contains the following segments:\n\n");
    printf("Index  %16s   Virt. addr. start    Virt. addr. end      Flags\n", "Type");
    for (int i = 0; i < c_ehdr->e_phnum; i++) {
        printf("[%4d] %16s   0x%016lx - 0x%016lx   %c %c %c\n",
               i, elf_seg_type_to_str(c_phdrs[i].p_type),
               c_phdrs[i].p_vaddr,
               c_phdrs[i].p_vaddr + c_phdrs[i].p_memsz,
               c_phdrs[i].p_flags & PF_R ? 'R' : ' ',
               c_phdrs[i].p_flags & PF_W ? 'W' : ' ',
               c_phdrs[i].p_flags & PF_X ? 'X' : ' ');
    }

    /* Search for text segments! */
    int core_text_seg_index = -1;

    printf("\n[*] Valid text segments: ");
    for (int i = 0; i < c_ehdr->e_phnum; i++) {
        /* Read first 4 bytes of the segment to see if it is ELF */
        char *seg_data = &c->data[c_phdrs[i].p_offset];
        if (c_phdrs[i].p_type == PT_LOAD &&
            c_phdrs[i].p_flags == (PF_R | PF_X) &&
            strncmp(seg_data, ELFMAG, SELFMAG) == 0) {
            printf("%d ", i);
            if ((c_phdrs[i].p_vaddr & (~0xfffff)) == 0x400000)
                core_text_seg_index = i;
        }
    }
    printf("\n");
    if (core_text_seg_index == -1) {
        printf("Unable to find a text segment near virtual address 0x400000, "
               "please specify a text segment index (usually 1): ");
        if (scanf("%d", &core_text_seg_index) != 1) {
            core_text_seg_index = 1;
            printf("Choose default value.");
        }
    }
    printf("[*] Text segment index = %d\n", core_text_seg_index);

    /* Retrive text segment data */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(c->data + c_phdrs[core_text_seg_index].p_offset);
    return ehdr->e_entry;
}
