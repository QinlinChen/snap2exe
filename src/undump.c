
#include "undump.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#include "elfcommon.h"

undumped_program *new_undumped_program()
{
    undumped_program *p = malloc(sizeof(*p));
    if (!p)
        return NULL;

    memset(p, 0, sizeof(*p));

    /* e_entry: to be filled later */
    p->ehdr.e_ident[0] = ELFMAG0;
    p->ehdr.e_ident[1] = ELFMAG1;
    p->ehdr.e_ident[2] = ELFMAG2;
    p->ehdr.e_ident[3] = ELFMAG3;
    p->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    p->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    p->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    p->ehdr.e_type = ET_EXEC;
    p->ehdr.e_machine = EM_X86_64;
    p->ehdr.e_version = EV_CURRENT;
    p->ehdr.e_phoff = sizeof(Elf64_Ehdr);
    p->ehdr.e_ehsize = sizeof(p->ehdr);
    p->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    p->ehdr.e_phnum = 1; /* Initially we have one metadata program header. */
    p->ehdr.e_shstrndx = SHN_UNDEF;

    /* To be filled on flushed to file:
     *   p_vaddr
     *   p_paddr
     *   p_filesz
     *   p_memsz
     */
    p->metadata_phdr.p_type = PT_LOAD;
    p->metadata_phdr.p_flags = PF_R | PF_X;
    p->metadata_phdr.p_offset = 0;
    p->metadata_phdr.p_align = PAGE_SIZE;

    return p;
}

static int copy_dumped_segs(undumped_program *prog, struct core *c);
static undump_segment *undump_add_segment(undumped_program *p, char *content, Elf64_Phdr *phdr);
static uintptr_t add_restore_seg(undumped_program *prog, struct core *c);
static char *generate_restore_code(int size, struct core *c);
static uintptr_t find_available_vaddr(undumped_program *p);

undumped_program *undump(struct core *c)
{
    undumped_program *prog = new_undumped_program();
    if (!prog)
        return NULL;

    copy_dumped_segs(prog, c);
    prog->ehdr.e_entry = add_restore_seg(prog, c);
    // prog->ehdr.e_entry = find_core_entry_point(c);

    return prog;
}

#define USER_SPACE_END  0x7fffffffffffULL

static int copy_dumped_segs(undumped_program *prog, struct core *c)
{
    Elf64_Ehdr *c_ehdr = elf_get_elf_header(c->data);
    Elf64_Phdr *c_phdrs = elf_get_program_headers(c->data);

    for (int i = 0; i < c_ehdr->e_phnum; i++) {
        if (c_phdrs[i].p_type == PT_LOAD && c_phdrs[i].p_vaddr <= USER_SPACE_END) {
            undump_add_segment(prog, c->data + c_phdrs[i].p_offset, &c_phdrs[i]);
        }
    }

    return 1;
}

static undump_segment *undump_add_segment(undumped_program *p, char *content, Elf64_Phdr *phdr)
{
    /* Will add a segment as and a relevant program header. */
    p->n_segs++;
    p->segments = realloc(p->segments, p->n_segs * sizeof(undump_segment));
    assert(p->segments);
    undump_segment *new_seg = &p->segments[p->n_segs - 1];

    memcpy(&new_seg->phdr, phdr, sizeof(*phdr));
    new_seg->phdr.p_paddr = new_seg->phdr.p_vaddr;

    if (content) {
        new_seg->segment = malloc(new_seg->phdr.p_filesz);
        assert(new_seg->segment);
        memcpy(new_seg->segment, content, new_seg->phdr.p_filesz);
    } else { /* If content is NULL, we aren't copying anything... */
        new_seg->segment = NULL;
    }

    (p->ehdr.e_phnum)++;
    return new_seg;
}

static uintptr_t add_restore_seg(undumped_program *prog, struct core *c)
{
    const int size = 512; /* should be more than enough */
    char *restore_code = generate_restore_code(size, c);
    assert(restore_code);

    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_vaddr = find_available_vaddr(prog);
    phdr.p_filesz = size;
    phdr.p_memsz = phdr.p_filesz;
    phdr.p_align = PAGE_SIZE;

    undump_add_segment(prog, restore_code, &phdr);
    printf("Generate restore segment at 0x%lx\n", phdr.p_vaddr);

    return phdr.p_vaddr;
}

#define ADD_BYTES(data, var, size) \
    do { \
        uint##size##_t tmp_var = (var); \
        memcpy((data), &tmp_var, sizeof(tmp_var)); \
        (data) += sizeof(tmp_var); \
    } while (0)

#define ADD_B(data, var) ADD_BYTES(data, var, 8)
#define ADD_W(data, var) ADD_BYTES(data, var, 16)
#define ADD_L(data, var) ADD_BYTES(data, var, 32)
#define ADD_Q(data, var) ADD_BYTES(data, var, 64)

#define ADD_MOV_I2AX(data, imm) \
    do { ADD_W(data, 0xb866); ADD_W(data, imm); } while (0)

#define ADD_MOV_AX2ES(data) ADD_W(data, 0xc08e)
#define ADD_MOV_AX2CS(data) ADD_W(data, 0xc88e)
#define ADD_MOV_AX2SS(data) ADD_W(data, 0xd08e)
#define ADD_MOV_AX2DS(data) ADD_W(data, 0xd88e)
#define ADD_MOV_AX2FS(data) ADD_W(data, 0xe08e)
#define ADD_MOV_AX2GS(data) ADD_W(data, 0xe88e)

#define ADD_OPW_IQ(data, op, imm) \
    do { ADD_W(data, op); ADD_Q(data, imm); } while (0)

#define ADD_MOV_I2RAX(data, imm) ADD_OPW_IQ(data, 0xb848, imm)
#define ADD_MOV_I2RCX(data, imm) ADD_OPW_IQ(data, 0xb948, imm)
#define ADD_MOV_I2RDX(data, imm) ADD_OPW_IQ(data, 0xba48, imm)
#define ADD_MOV_I2RBX(data, imm) ADD_OPW_IQ(data, 0xbb48, imm)
#define ADD_MOV_I2RSP(data, imm) ADD_OPW_IQ(data, 0xbc48, imm)
#define ADD_MOV_I2RBP(data, imm) ADD_OPW_IQ(data, 0xbd48, imm)
#define ADD_MOV_I2RSI(data, imm) ADD_OPW_IQ(data, 0xbe48, imm)
#define ADD_MOV_I2RDI(data, imm) ADD_OPW_IQ(data, 0xbf48, imm)
#define ADD_MOV_I2R8(data, imm)  ADD_OPW_IQ(data, 0xb849, imm)
#define ADD_MOV_I2R9(data, imm)  ADD_OPW_IQ(data, 0xb949, imm)
#define ADD_MOV_I2R10(data, imm) ADD_OPW_IQ(data, 0xba49, imm)
#define ADD_MOV_I2R11(data, imm) ADD_OPW_IQ(data, 0xbb49, imm)
#define ADD_MOV_I2R12(data, imm) ADD_OPW_IQ(data, 0xbc49, imm)
#define ADD_MOV_I2R13(data, imm) ADD_OPW_IQ(data, 0xbd49, imm)
#define ADD_MOV_I2R14(data, imm) ADD_OPW_IQ(data, 0xbe49, imm)
#define ADD_MOV_I2R15(data, imm) ADD_OPW_IQ(data, 0xbf49, imm)

#define ADD_PUSH_RAX(data)  ADD_B(data, 0x50)
#define ADD_POPF(data)      ADD_B(data, 0x9d)
#define ADD_RET(data)       ADD_B(data, 0xc3)
#define ADD_SYSCALL(data)   ADD_W(data, 0x050f);

static char *generate_restore_code(int size, struct core *c)
{
    /* There are several ways to do this. One being the automatic generation
     * of assembly file to do that and then compiling it, however, this would
     * require an assembler present. Instead, a simpler approach can be used,
     * simply write the exact machine code...
     */
    char *data = malloc(size);
    if (!data)
        return NULL;
    char *start = data;

    regs *r = &(c->status->pr_reg);

    // ADD_MOV_I2AX(data, r->es);
    // ADD_MOV_AX2ES(data);
    // ADD_MOV_I2AX(data, r->ss);
    // ADD_MOV_AX2SS(data);
    // ADD_MOV_I2AX(data, r->ds);
    // ADD_MOV_AX2DS(data);
    // ADD_MOV_I2AX(data, r->fs);
    // ADD_MOV_AX2FS(data);
    // ADD_MOV_I2AX(data, r->gs);
    // ADD_MOV_AX2GS(data);

    /* Restore fs.base for the TLS usage. */
    ADD_MOV_I2RAX(data, SYS_arch_prctl);
    ADD_MOV_I2RDI(data, ARCH_SET_FS);
    ADD_MOV_I2RSI(data, r->fs_base);
    ADD_SYSCALL(data);

    ADD_MOV_I2RBX(data, r->rbx);
    ADD_MOV_I2RCX(data, r->rcx);
    ADD_MOV_I2RDX(data, r->rdx);
    ADD_MOV_I2RSP(data, r->rsp);
    ADD_MOV_I2RBP(data, r->rbp);
    ADD_MOV_I2RSI(data, r->rsi);
    ADD_MOV_I2RDI(data, r->rdi);
    ADD_MOV_I2R8(data, r->r8);
    ADD_MOV_I2R9(data, r->r9);
    ADD_MOV_I2R10(data, r->r10);
    ADD_MOV_I2R11(data, r->r11);
    ADD_MOV_I2R12(data, r->r12);
    ADD_MOV_I2R13(data, r->r13);
    ADD_MOV_I2R14(data, r->r14);
    ADD_MOV_I2R15(data, r->r15);

    ADD_MOV_I2RAX(data, r->eflags);
    ADD_PUSH_RAX(data);
    ADD_POPF(data);

    ADD_MOV_I2RAX(data, r->rip);
    ADD_PUSH_RAX(data);

    ADD_MOV_I2RAX(data, r->rax);

    ADD_RET(data);

    return start;
}

static uintptr_t find_available_vaddr(undumped_program *p)
{
    // uintptr_t next_vaddr = 0, align = 0;

    // for (int i = 0; i < p->n_segs; i++) {
    //     uintptr_t vaddr_end = p->segments[i].phdr.p_vaddr + p->segments[i].phdr.p_memsz;
    //     if (vaddr_end > next_vaddr) {
    //         next_vaddr = vaddr_end;
    //         align = p->segments[i].phdr.p_align;
    //     }
    // }

    // return (next_vaddr - (next_vaddr % align) + align);
    return 0x200000ULL; // TODO: fix this hard code.
}

#define PAGE_ALIGN(off) (((off) + PAGE_SIZE) & PAGE_MASK);

static void update_metadata_phdr(undumped_program *p);

int write_undumped(int fd, undumped_program *p)
{
    update_metadata_phdr(p);

    /* The offset has to be page aligned!  */
    off_t off = PAGE_ALIGN(p->ehdr.e_phoff + p->ehdr.e_phnum*p->ehdr.e_phentsize);
    if (lseek(fd, off, SEEK_SET) < 0)
        return -1;

    for (int i = 0; i < p->n_segs; i++) {
        undump_segment *wr_seg = &p->segments[i];
        printf("Writing segment with offset 0x%lx, vaddr 0x%lx...",
               wr_seg->phdr.p_offset, wr_seg->phdr.p_vaddr);
        if (!wr_seg->segment) {
            printf("No data for segment at 0x%lx\n", wr_seg->phdr.p_vaddr);
            continue;
        }

        if (write(fd, wr_seg->segment, wr_seg->phdr.p_filesz) != wr_seg->phdr.p_filesz)
            return -1;

        wr_seg->phdr.p_offset = off;
        off = PAGE_ALIGN(off + wr_seg->phdr.p_filesz);
        if (lseek(fd, off, SEEK_SET) < 0)
            return -1;
        printf("Done.\n");
    }

    off = p->metadata_phdr.p_offset;
    assert(off == 0);
    if (lseek(fd, off, SEEK_SET) < 0)
        return -1;

    printf("Writing metadata segment with offset 0x%lx, vaddr 0x%lx...",
           p->metadata_phdr.p_offset, p->metadata_phdr.p_vaddr);
    if (write(fd, &p->ehdr, sizeof(p->ehdr)) != sizeof(p->ehdr))
        return -1;

    if (lseek(fd, p->ehdr.e_phoff, SEEK_SET) < 0)
        return -1;
    if (write(fd, &(p->metadata_phdr),
              sizeof(p->metadata_phdr)) != sizeof(p->metadata_phdr))
        return -1;

    for (int i = 0; i < p->n_segs; i++) {
        Elf64_Phdr *wr_phdr = &p->segments[i].phdr;
        if (write(fd, wr_phdr, sizeof(*wr_phdr)) != sizeof(*wr_phdr))
            return -1;
    }

    printf("Done.\n");
    return 0;
}

static void update_metadata_phdr(undumped_program *p)
{
    uintptr_t vaddr = 0x300000;
    size_t metadata_size = p->ehdr.e_phoff + p->ehdr.e_phnum * p->ehdr.e_phentsize;

    p->metadata_phdr.p_vaddr = vaddr;
    p->metadata_phdr.p_paddr = vaddr;
    p->metadata_phdr.p_memsz = metadata_size;
    p->metadata_phdr.p_filesz = metadata_size;
}