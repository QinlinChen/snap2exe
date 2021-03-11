#include "sys.h"
#include "exe.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#include "elfcommon.h"

int exe_init(struct exe *ex)
{
    memset(ex, 0, sizeof(*ex));

    /* e_entry: to be filled later */
    ex->ehdr.e_ident[0] = ELFMAG0;
    ex->ehdr.e_ident[1] = ELFMAG1;
    ex->ehdr.e_ident[2] = ELFMAG2;
    ex->ehdr.e_ident[3] = ELFMAG3;
    ex->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ex->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ex->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ex->ehdr.e_type = ET_EXEC;
    ex->ehdr.e_machine = EM_X86_64;
    ex->ehdr.e_version = EV_CURRENT;
    ex->ehdr.e_phoff = sizeof(ex->ehdr);
    ex->ehdr.e_ehsize = sizeof(ex->ehdr);
    ex->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ex->ehdr.e_phnum = 1; /* Initially we have a program header for metadata. */
    ex->ehdr.e_shstrndx = SHN_UNDEF;

    /* To be filled when flushed to file:
     *   metadata_phdr.p_vaddr
     *   metadata_phdr.p_paddr
     *   metadata_phdr.p_filesz
     *   metadata_phdr.p_memsz
     */
    ex->metadata_phdr.p_type = PT_LOAD;
    ex->metadata_phdr.p_flags = PF_R | PF_X;
    ex->metadata_phdr.p_offset = 0;
    ex->metadata_phdr.p_align = PAGE_SIZE;

    return 0;
}

void exe_free_segs(struct exe *ex)
{
    for (int i = 0; i < ex->n_segs; i++)
        if (ex->segs[i].data)
            free(ex->segs[i].data);
    memset(ex->segs, 0, sizeof(ex->segs));
}

static int exe_dup_segs(struct exe *ex, struct snapshot *ss);
static int exe_add_seg(struct exe *ex, Elf64_Phdr *phdr, char *data);
static uintptr_t exe_add_restore_seg(struct exe *ex, struct snapshot *ss);
static char *generate_restore_code(int size, struct snapshot *ss);
static uintptr_t find_available_vaddr(struct exe *ex);

int exe_build_from_snapshot(struct exe *ex, struct snapshot *ss)
{
    exe_init(ex);

    if (exe_dup_segs(ex, ss) != 0)
        return -1;

    ex->ehdr.e_entry = exe_add_restore_seg(ex, ss);
    if (ex->ehdr.e_entry == 0) {
        exe_free_segs(ex);
        return -1;
    }

    return 0;
}

#define USER_SPACE_END  0x800000000000ULL

static int exe_dup_segs(struct exe *ex, struct snapshot *ss)
{
    struct proc_map *map = ss->maps;
    for (int i = 0; i < ss->n_maps; i++, map++) {
        if ((uintptr_t)map->start >= USER_SPACE_END)
            continue;

        Elf64_Phdr phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.p_type = PT_LOAD;
        if (map->prot & PROT_READ)
            phdr.p_flags |= PF_R;
        if (map->prot & PROT_WRITE)
            phdr.p_flags |= PF_W;
        if (map->prot & PROT_EXEC)
            phdr.p_flags |= PF_X;
        phdr.p_vaddr = (uintptr_t)map->start;
        phdr.p_paddr = phdr.p_vaddr;
        phdr.p_memsz = map->end - map->start;
        phdr.p_filesz = phdr.p_memsz;
        phdr.p_align = PAGE_SIZE;
        /* phdr.p_offset will be filled when flushed to file. */

        char *data = alloc_read_proc_map(ss->pid, map);
        if (exe_add_seg(ex, &phdr, data) < 0) {
            printf("exceed MAX_SEGMENTS\n");
            exe_free_segs(ex);
            return -1;
        }
    }

    return 0;
}

/* Add a segment data and a relevant program header. */
static int exe_add_seg(struct exe *ex, Elf64_Phdr *phdr, char *data)
{
    if (ex->n_segs >= MAX_SEGMENTS)
        return -1;

    struct segment *new_seg = &ex->segs[ex->n_segs];
    ex->n_segs++;
    memcpy(&new_seg->phdr, phdr, sizeof(*phdr));
    new_seg->phdr.p_paddr = new_seg->phdr.p_vaddr;
    new_seg->data = data;
    (ex->ehdr.e_phnum)++;

    return 0;
}

static uintptr_t exe_add_restore_seg(struct exe *ex, struct snapshot *ss)
{
    const int size = 512; /* should be more than enough */
    char *restore_code = generate_restore_code(size, ss);
    if (!restore_code)
        return 0;

    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_vaddr = find_available_vaddr(ex);
    phdr.p_filesz = size;
    phdr.p_memsz = phdr.p_filesz;
    phdr.p_align = PAGE_SIZE;

    if (exe_add_seg(ex, &phdr, restore_code) != 0) {
        free(restore_code);
        return -1;
    }

    printf("Generate restore segment at 0x%lx\n", phdr.p_vaddr);
    return phdr.p_vaddr;
}

#define ADD_BYTES(buf, var, size) \
    do { \
        uint##size##_t tmp_var = (var); \
        memcpy((buf), &tmp_var, sizeof(tmp_var)); \
        (buf) += sizeof(tmp_var); \
    } while (0)

#define ADD_B(buf, var) ADD_BYTES(buf, var, 8)
#define ADD_W(buf, var) ADD_BYTES(buf, var, 16)
#define ADD_L(buf, var) ADD_BYTES(buf, var, 32)
#define ADD_Q(buf, var) ADD_BYTES(buf, var, 64)

#define ADD_MOV_I2AX(buf, imm) \
    do { ADD_W(buf, 0xb866); ADD_W(buf, imm); } while (0)

#define ADD_MOV_AX2ES(buf) ADD_W(buf, 0xc08e)
#define ADD_MOV_AX2CS(buf) ADD_W(buf, 0xc88e)
#define ADD_MOV_AX2SS(buf) ADD_W(buf, 0xd08e)
#define ADD_MOV_AX2DS(buf) ADD_W(buf, 0xd88e)
#define ADD_MOV_AX2FS(buf) ADD_W(buf, 0xe08e)
#define ADD_MOV_AX2GS(buf) ADD_W(buf, 0xe88e)

#define ADD_OPW_IQ(buf, op, imm) \
    do { ADD_W(buf, op); ADD_Q(buf, imm); } while (0)

#define ADD_MOV_I2RAX(buf, imm) ADD_OPW_IQ(buf, 0xb848, imm)
#define ADD_MOV_I2RCX(buf, imm) ADD_OPW_IQ(buf, 0xb948, imm)
#define ADD_MOV_I2RDX(buf, imm) ADD_OPW_IQ(buf, 0xba48, imm)
#define ADD_MOV_I2RBX(buf, imm) ADD_OPW_IQ(buf, 0xbb48, imm)
#define ADD_MOV_I2RSP(buf, imm) ADD_OPW_IQ(buf, 0xbc48, imm)
#define ADD_MOV_I2RBP(buf, imm) ADD_OPW_IQ(buf, 0xbd48, imm)
#define ADD_MOV_I2RSI(buf, imm) ADD_OPW_IQ(buf, 0xbe48, imm)
#define ADD_MOV_I2RDI(buf, imm) ADD_OPW_IQ(buf, 0xbf48, imm)
#define ADD_MOV_I2R8(buf, imm)  ADD_OPW_IQ(buf, 0xb849, imm)
#define ADD_MOV_I2R9(buf, imm)  ADD_OPW_IQ(buf, 0xb949, imm)
#define ADD_MOV_I2R10(buf, imm) ADD_OPW_IQ(buf, 0xba49, imm)
#define ADD_MOV_I2R11(buf, imm) ADD_OPW_IQ(buf, 0xbb49, imm)
#define ADD_MOV_I2R12(buf, imm) ADD_OPW_IQ(buf, 0xbc49, imm)
#define ADD_MOV_I2R13(buf, imm) ADD_OPW_IQ(buf, 0xbd49, imm)
#define ADD_MOV_I2R14(buf, imm) ADD_OPW_IQ(buf, 0xbe49, imm)
#define ADD_MOV_I2R15(buf, imm) ADD_OPW_IQ(buf, 0xbf49, imm)

#define ADD_PUSH_RAX(buf)  ADD_B(buf, 0x50)
#define ADD_POPF(buf)      ADD_B(buf, 0x9d)
#define ADD_RET(buf)       ADD_B(buf, 0xc3)
#define ADD_SYSCALL(buf)   ADD_W(buf, 0x050f);

static char *generate_restore_code(int size, struct snapshot *ss)
{
    /* There are several ways to do this. One being the automatic generation
     * of assembly file to do that and then compiling it, however, this would
     * require an assembler present. Instead, a simpler approach can be used,
     * simply write the exact machine code...
     */
    char *buf = malloc(size);
    if (!buf)
        return NULL;
    char *start = buf;

    struct user_regs_struct *r = &ss->regs;

    // ADD_MOV_I2AX(buf, r->es);
    // ADD_MOV_AX2ES(buf);
    // ADD_MOV_I2AX(buf, r->ss);
    // ADD_MOV_AX2SS(buf);
    // ADD_MOV_I2AX(buf, r->ds);
    // ADD_MOV_AX2DS(buf);
    // ADD_MOV_I2AX(buf, r->fs);
    // ADD_MOV_AX2FS(buf);
    // ADD_MOV_I2AX(buf, r->gs);
    // ADD_MOV_AX2GS(buf);

    /* Restore fs.base for TLS usage. */
    ADD_MOV_I2RAX(buf, SYS_arch_prctl);
    ADD_MOV_I2RDI(buf, ARCH_SET_FS);
    ADD_MOV_I2RSI(buf, r->fs_base);
    ADD_SYSCALL(buf);

    ADD_MOV_I2RBX(buf, r->rbx);
    ADD_MOV_I2RCX(buf, r->rcx);
    ADD_MOV_I2RDX(buf, r->rdx);
    ADD_MOV_I2RSP(buf, r->rsp);
    ADD_MOV_I2RBP(buf, r->rbp);
    ADD_MOV_I2RSI(buf, r->rsi);
    ADD_MOV_I2RDI(buf, r->rdi);
    ADD_MOV_I2R8(buf, r->r8);
    ADD_MOV_I2R9(buf, r->r9);
    ADD_MOV_I2R10(buf, r->r10);
    ADD_MOV_I2R11(buf, r->r11);
    ADD_MOV_I2R12(buf, r->r12);
    ADD_MOV_I2R13(buf, r->r13);
    ADD_MOV_I2R14(buf, r->r14);
    ADD_MOV_I2R15(buf, r->r15);

    ADD_MOV_I2RAX(buf, r->eflags);
    ADD_PUSH_RAX(buf);
    ADD_POPF(buf);

    ADD_MOV_I2RAX(buf, r->rip);
    ADD_PUSH_RAX(buf);

    ADD_MOV_I2RAX(buf, r->rax);

    ADD_RET(buf);

    return start;
}

static uintptr_t find_available_vaddr(struct exe *ex)
{
    return 0x200000UL; // TODO: fix this hard code.
}

#define PAGE_ALIGN(off) (((off) + PAGE_SIZE - 1) & PAGE_MASK);

static void update_metadata_phdr(struct exe *ex);

int exe_save(int fd, struct exe *ex)
{
    update_metadata_phdr(ex);

    /* The offset has to be page aligned!  */
    off_t off = PAGE_ALIGN(ex->ehdr.e_phoff + ex->ehdr.e_phnum*ex->ehdr.e_phentsize);
    if (lseek(fd, off, SEEK_SET) < 0)
        return -1;

    for (int i = 0; i < ex->n_segs; i++) {
        struct segment *wr_seg = &ex->segs[i];
        printf("Writing segment with offset 0x%lx, vaddr 0x%lx...",
               wr_seg->phdr.p_offset, wr_seg->phdr.p_vaddr);
        if (!wr_seg->data) {
            printf("No data for segment at 0x%lx\n", wr_seg->phdr.p_vaddr);
            continue;
        }

        if (write(fd, wr_seg->data, wr_seg->phdr.p_filesz) != wr_seg->phdr.p_filesz)
            return -1;

        wr_seg->phdr.p_offset = off;
        off = PAGE_ALIGN(off + wr_seg->phdr.p_filesz);
        if (lseek(fd, off, SEEK_SET) < 0)
            return -1;
        printf("Done.\n");
    }

    off = ex->metadata_phdr.p_offset;
    assert(off == 0);
    if (lseek(fd, off, SEEK_SET) < 0)
        return -1;

    printf("Writing metadata segment with offset 0x%lx, vaddr 0x%lx...",
           ex->metadata_phdr.p_offset, ex->metadata_phdr.p_vaddr);
    if (write(fd, &ex->ehdr, sizeof(ex->ehdr)) != sizeof(ex->ehdr))
        return -1;

    if (lseek(fd, ex->ehdr.e_phoff, SEEK_SET) < 0)
        return -1;
    if (write(fd, &(ex->metadata_phdr),
              sizeof(ex->metadata_phdr)) != sizeof(ex->metadata_phdr))
        return -1;

    for (int i = 0; i < ex->n_segs; i++) {
        Elf64_Phdr *wr_phdr = &ex->segs[i].phdr;
        if (write(fd, wr_phdr, sizeof(*wr_phdr)) != sizeof(*wr_phdr))
            return -1;
    }

    printf("Done.\n");
    return 0;
}

static void update_metadata_phdr(struct exe *ex)
{
    uintptr_t vaddr = 0x300000UL; // TODO: Fix this hard code.
    size_t metadata_size = ex->ehdr.e_phoff + ex->ehdr.e_phnum * ex->ehdr.e_phentsize;

    ex->metadata_phdr.p_vaddr = vaddr;
    ex->metadata_phdr.p_paddr = vaddr;
    ex->metadata_phdr.p_memsz = metadata_size;
    ex->metadata_phdr.p_filesz = metadata_size;
}