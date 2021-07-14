#include "sys.h"
#include "config.h"
#include "exe.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#include "snap2exe/snap2exe.h"
#include "elfcommon.h"
#include "utils.h"
#include "codegen.h"

static int exe_init(struct exe *ex);
static int exe_dup_segs(struct exe *ex, struct snapshot *ss);
static int exe_add_seg(struct exe *ex, Elf64_Phdr *phdr, char *data);
static void exe_free_segs(struct exe *ex);
static uintptr_t exe_add_restore_seg(struct exe *ex, struct snapshot *ss);
static char *generate_restore_code(struct snapshot *ss, uintptr_t base, size_t *size);
static uintptr_t find_available_vaddr(struct exe *ex);
static void update_metadata_phdr(struct exe *ex);

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

static int exe_init(struct exe *ex)
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

#define USER_SPACE_END  0x800000000000ULL

static int exe_dup_segs(struct exe *ex, struct snapshot *ss)
{
    char *data = NULL;
    Elf64_Phdr phdr;
    struct mem_map *pmap = ss->maps;

    for (int i = 0; i < ss->n_maps; i++, pmap++) {
        if ((uintptr_t)pmap->start >= USER_SPACE_END)
            continue;

        memset(&phdr, 0, sizeof(phdr));
        phdr.p_type = PT_LOAD;
        if (pmap->prot & PROT_READ)
            phdr.p_flags |= PF_R;
        if (pmap->prot & PROT_WRITE)
            phdr.p_flags |= PF_W;
        if (pmap->prot & PROT_EXEC)
            phdr.p_flags |= PF_X;
        phdr.p_vaddr = (uintptr_t)pmap->start;
        phdr.p_paddr = phdr.p_vaddr;
        phdr.p_memsz = pmap->end - pmap->start;
        phdr.p_filesz = phdr.p_memsz;
        phdr.p_align = PAGE_SIZE;
        /* phdr.p_offset will be filled when flushed to file. */

        data = fetch_mem_map(ss->pid, pmap);
        if (!data)
            continue; /* Ignore this error; dump mem maps as many as possible. */
        if (exe_add_seg(ex, &phdr, data) < 0)
            goto errout;
    }

    return 0;

errout:
    exe_free_segs(ex);
    if (data)
        free(data);
    return -1;
}

/* Add a segment data and a relevant program header. */
static int exe_add_seg(struct exe *ex, Elf64_Phdr *phdr, char *data)
{
    if (ex->n_segs >= MAX_SEGMENTS) {
        s2e_lib_err("exceed MAX_SEGMENTS");
        return -1;
    }

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
    size_t size;
    uintptr_t base = find_available_vaddr(ex);
    char *restore_code = generate_restore_code(ss, base, &size);
    if (!restore_code)
        return 0;

    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_vaddr = base;
    phdr.p_filesz = size;
    phdr.p_memsz = phdr.p_filesz;
    phdr.p_align = PAGE_SIZE;

    if (exe_add_seg(ex, &phdr, restore_code) != 0) {
        free(restore_code);
        return 0;
    }

    return phdr.p_vaddr;
}

const char *tmpl_text_start =
    ".global _start\n"
    ".text\n"
    "_start:\n";

const char *tmpl_restore_fsbase =
    "    movq $%lld, %%rax\n"
    "    movq $%lld, %%rdi\n"
    "    movq $%lld, %%rsi\n"
    "    syscall\n";

const char *tmpl_restore_general_regs =
    "    movq $%lld, %%rbx\n"
    "    movq $%lld, %%rcx\n"
    "    movq $%lld, %%rdx\n"
    "    movq $%lld, %%rsp\n"
    "    movq $%lld, %%rbp\n"
    "    movq $%lld, %%rsi\n"
    "    movq $%lld, %%rdi\n"
    "    movq $%lld, %%r8\n"
    "    movq $%lld, %%r9\n"
    "    movq $%lld, %%r10\n"
    "    movq $%lld, %%r11\n"
    "    movq $%lld, %%r12\n"
    "    movq $%lld, %%r13\n"
    "    movq $%lld, %%r14\n"
    "    movq $%lld, %%r15\n";

const char *tmpl_restore_eflags =
    "    movq $%lld, %%rax\n"
    "    pushq %%rax\n"
    "    popfq\n";

const char *tmpl_push_rip =
    "    movq $%lld, %%rax\n"
    "    pushq %%rax\n";

const char *tmpl_restore_rax =
    "    movq $%lld, %%rax\n";

const char *tmpl_ret =
    "    retq\n";

/* There are several ways to do this, one being the automatic generation
   of assembly file to do that and then compiling it. However, this would
   require an assembler present. Instead, a simpler approach can be used,
   simply write the exact machine code... */
static char *generate_restore_code(struct snapshot *ss, uintptr_t base, size_t *size)
{
    // char tmpfile[] = "/tmp/snap2exe_restore.XXXXXX";
    // int fd = mkstemp(tmpfile);
    // FILE *fp = fdopen(fd, "w");

    // struct user_regs_struct *r = &ss->regs;
    // fprintf(fp, tmpl_text_start);
    // fprintf(fp, tmpl_restore_general_regs,
    //     r->rbx, r->rcx, r->rdx, r->rsp, r->rbp, r->rsi, r->rdi,
    //     r->r8, r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15);
    // fprintf(fp, tmpl_restore_eflags, r->eflags);
    // fprintf(fp, tmpl_push_rip, r->rip);
    // fprintf(fp, tmpl_ret);
    // fclose(fp);
    // close(fd);

    // char restore_code_file[MAXLINE];
    // snprintf(restore_code_file, sizeof(restore_code_file), "%s.exe", tmpfile);
    // char cmd[MAXLINE];
    // snprintf(cmd, sizeof(cmd), "gcc -nostdlib -static -pie %s -o %s", tmpfile, restore_code_file);
    // system(cmd);

    char *buf = malloc(2*PAGE_SIZE); /* Should be more than enough. */
    if (!buf)
        return NULL;
    if (size)
        *size = 2*PAGE_SIZE;

    char *cbuf = buf;
    char *dbuf = buf + PAGE_SIZE;
    // uintptr_t data_base = base + PAGE_SIZE;
    struct user_regs_struct *r = &ss->regs;

    /* Restore fs.base for TLS usage. */
    INS_SYSCALL2(cbuf, SYS_arch_prctl, ARCH_SET_FS, r->fs_base);

    /* Reopen files. */
    struct fdstat *pfdstat = ss->fdstat;
    char path[MAXPATH];
    for (int i = 0; i < ss->n_fds; i++, pfdstat++) {
        int fd = pfdstat->fd;
        if (snprintf(path, sizeof(path), "%s/%d",
                     ss->snapshot_dir, fd) >= sizeof(path)) {
            s2e_unix_err("exceed max path length");
            goto errout;
        }
        if (access(path, F_OK) != 0)
            continue;

        INS_SYSCALL3(cbuf, SYS_open, base + (dbuf - buf), pfdstat->oflag, 0);
        INS_STR(dbuf, path);

        INS_CMPL_EAX(cbuf, 0x0);
        INS_JL(cbuf, 0x56);
        INS_CMPL_EAX(cbuf, fd);
        INS_JE(cbuf, 0x2c);

        INS_PUSH_RAX(cbuf);
        INS_PUSH_RAX(cbuf);
        INS_B(cbuf, 0x48); INS_W(cbuf, 0xc789);
        INS_MOV_I2RSI(cbuf, fd);
        INS_SYSCALL0(cbuf, SYS_dup2);
        INS_POP_RAX(cbuf);
        INS_B(cbuf, 0x56); INS_W(cbuf, 0xc789);
        INS_SYSCALL0(cbuf, SYS_close);
        INS_POP_RAX(cbuf);

        INS_B(cbuf, 0x48); INS_W(cbuf, 0xc789);
        INS_MOV_I2RSI(cbuf, pfdstat->offset);
        INS_MOV_I2RDX(cbuf, SEEK_SET);
        INS_SYSCALL0(cbuf, SYS_lseek);

        assert(cbuf < buf + PAGE_SIZE);
        assert(dbuf < buf + 2*PAGE_SIZE);
    }

    /* Recover registers (except rax and rip).
       Note that rsp is going to point to the original stack */
    INS_MOV_I2RBX(cbuf, r->rbx);
    INS_MOV_I2RCX(cbuf, r->rcx);
    INS_MOV_I2RDX(cbuf, r->rdx);
    INS_MOV_I2RSP(cbuf, r->rsp);
    INS_MOV_I2RBP(cbuf, r->rbp);
    INS_MOV_I2RSI(cbuf, r->rsi);
    INS_MOV_I2RDI(cbuf, r->rdi);
    INS_MOV_I2R8(cbuf, r->r8);
    INS_MOV_I2R9(cbuf, r->r9);
    INS_MOV_I2R10(cbuf, r->r10);
    INS_MOV_I2R11(cbuf, r->r11);
    INS_MOV_I2R12(cbuf, r->r12);
    INS_MOV_I2R13(cbuf, r->r13);
    INS_MOV_I2R14(cbuf, r->r14);
    INS_MOV_I2R15(cbuf, r->r15);

    /* Recover eflags */
    INS_MOV_I2RAX(cbuf, r->eflags);
    INS_PUSH_RAX(cbuf);
    INS_POPF(cbuf);

    /* Push rip for return. */
    INS_MOV_I2RAX(cbuf, r->rip);
    INS_PUSH_RAX(cbuf);

    /* Recover rax */
    INS_MOV_I2RAX(cbuf, r->rax);

    INS_RET(cbuf);

    return buf;

errout:
    free(buf);
    return NULL;
}

static uintptr_t find_available_vaddr(struct exe *ex)
{
    return 0x100000UL; // TODO: fix this hard code.
}

void exe_free(struct exe *ex)
{
    exe_free_segs(ex);
}

static void exe_free_segs(struct exe *ex)
{
    for (int i = 0; i < ex->n_segs; i++)
        if (ex->segs[i].data)
            free(ex->segs[i].data);
    memset(ex->segs, 0, sizeof(ex->segs[0])*ex->n_segs);
    ex->n_segs = 0;
}

#define PAGE_ROUNDUP(off) (((off) + PAGE_SIZE - 1) & PAGE_MASK);

int exe_save(int fd, struct exe *ex)
{
    update_metadata_phdr(ex);

    /* The offset has to be page aligned! */
    off_t off = PAGE_ROUNDUP(ex->ehdr.e_phoff + ex->ehdr.e_phnum*ex->ehdr.e_phentsize);
    if (lseek(fd, off, SEEK_SET) < 0) {
        s2e_unix_err("lseek error");
        return -1;
    }

    for (int i = 0; i < ex->n_segs; i++) {
        struct segment *wr_seg = &ex->segs[i];
        assert(wr_seg->data);
        if (write(fd, wr_seg->data, wr_seg->phdr.p_filesz) != wr_seg->phdr.p_filesz) {
            s2e_unix_err("write segment error");
            return -1;
        }
        wr_seg->phdr.p_offset = off;

        off = PAGE_ROUNDUP(off + wr_seg->phdr.p_filesz);
        if (lseek(fd, off, SEEK_SET) < 0) {
            s2e_unix_err("lseek error");
            return -1;
        }
    }

    /* Write metadata segment, i.e., elf header, program headers. */
    off = ex->metadata_phdr.p_offset;
    assert(off == 0);
    if (lseek(fd, off, SEEK_SET) < 0) {
        s2e_unix_err("lseek error");
        return -1;
    }
    if (write(fd, &ex->ehdr, sizeof(ex->ehdr)) != sizeof(ex->ehdr)) {
        s2e_unix_err("write elf header error");
        return -1;
    }

    if (lseek(fd, ex->ehdr.e_phoff, SEEK_SET) < 0) {
        s2e_unix_err("lseek error");
        return -1;
    }
    if (write(fd, &(ex->metadata_phdr),
              sizeof(ex->metadata_phdr)) != sizeof(ex->metadata_phdr)) {
        s2e_unix_err("write metadata program header error");
        return -1;
    }

    for (int i = 0; i < ex->n_segs; i++) {
        Elf64_Phdr *wr_phdr = &ex->segs[i].phdr;
        if (write(fd, wr_phdr, sizeof(*wr_phdr)) != sizeof(*wr_phdr)) {
            s2e_unix_err("write metadata program header error");
            return -1;
        }
    }

    return 0;
}

static void update_metadata_phdr(struct exe *ex)
{
    uintptr_t vaddr = 0x200000UL; // TODO: fix this hard code.
    size_t metadata_size = ex->ehdr.e_phoff + ex->ehdr.e_phnum * ex->ehdr.e_phentsize;

    ex->metadata_phdr.p_vaddr = vaddr;
    ex->metadata_phdr.p_paddr = vaddr;
    ex->metadata_phdr.p_memsz = metadata_size;
    ex->metadata_phdr.p_filesz = metadata_size;
}
