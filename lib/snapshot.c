#include "sys.h"
#include "config.h"
#include "snapshot.h"

#include <sys/mman.h>

#include "snap2exe/snap2exe.h"
#include "utils.h"

static int snapshot_init(struct snapshot *ss, const char *snapshot_dir, pid_t pid);
static int dump_user_status(struct snapshot *ss);
static int dump_kernel_status(struct snapshot *ss);
static int dump_env(struct snapshot *ss);

int snapshot_build(struct snapshot *ss, const char *snapshot_dir, pid_t pid)
{
    if (snapshot_init(ss, snapshot_dir, pid) != 0)
        return -1;
    if (dump_user_status(ss) < 0)
        return -1;
    if (dump_kernel_status(ss) < 0)
        return -1;
    if (dump_env(ss) < 0)
        return -1;
    return 0;
}

static int snapshot_init(struct snapshot *ss, const char *snapshot_dir, pid_t pid)
{
    ss->pid = pid;
    if (!abspath(snapshot_dir, ss->snapshot_dir, ARRAY_LEN(ss->snapshot_dir))) {
        s2e_unix_err("fail to get abspath of %s", snapshot_dir);
        return -1;
    }
    ss->n_maps = 0;
    ss->n_fds = 0;
    return 0;
}

static int dump_regs(struct snapshot *ss);
static int dump_mem_maps(struct snapshot *ss);
static int extract_mem_map(char *line, struct mem_map *map);
static int add_mem_map(struct snapshot *ss, struct mem_map *map);
static int str_to_prot(const char *perms);

static int dump_user_status(struct snapshot *ss)
{
    if (dump_regs(ss) < 0)
        return -1;
    if (dump_mem_maps(ss) < 0)
        return -1;
    return 0;
}

static int dump_regs(struct snapshot *ss)
{
    if (ptrace_getregs(ss->pid, &ss->regs) != 0) {
        s2e_unix_err("ptrace getregs error");
        return -1;
    }
    return 0;
}

/* Parse memory maps from /proc/[pid]/maps. */
static int dump_mem_maps(struct snapshot *ss)
{
    FILE *fp;
    char filepath[MAXPATH];
    snprintf(filepath, ARRAY_LEN(filepath), "/proc/%d/maps", ss->pid);
    if ((fp = fopen(filepath, "r")) == NULL) {
        s2e_unix_err("fail to open file: %s", filepath);
        goto errout;
    }

    char *rd_ret;
    char line[MAXLINE];
    struct mem_map map;
    while ((rd_ret = readline(fp, line, ARRAY_LEN(line))) != NULL) {
        if (rd_ret == (char *)-1)
            goto errout;
        int ret = extract_mem_map(line, &map);
        if (ret == -1)
            goto errout;
        if (ret == 0)
            continue;
        if (add_mem_map(ss, &map) < 0)
            goto errout;
    }

    fclose(fp);
    return 0;

errout:
    if (fp)
        fclose(fp);
    return -1;
}

static int extract_mem_map(char *line, struct mem_map *map)
{
    unsigned long start, end, offset, major, minor, inode;
    char perms[4], pathname[MAXPATH];

    int nscanf = sscanf(line, "%lx-%lx %4c %lx %lx:%lx %lu %s",
                        &start, &end, perms, &offset,
                        &major, &minor, &inode, pathname);
    if (nscanf < 7) {
        s2e_unix_err("parse /proc/pid/map error");
        return -1;
    }

    if (strncmp(perms, "---", 3) == 0)
        return 0; /* Maybe we can ignore this kind of maps. */

    if (strncmp(pathname, "[vvar]", MAXPATH) == 0
        || strncmp(pathname, "[vdso]", MAXPATH) == 0
        || strncmp(pathname, "[vsyscall]", MAXPATH) == 0)
        return 0;

    map->start = (void *)start;
    map->end = (void *)end;
    map->prot = str_to_prot(perms);
    return 1;
}

static int add_mem_map(struct snapshot *ss, struct mem_map *map)
{
    if (ss->n_maps >= MAX_MEM_MAPS) {
        s2e_lib_err("exccess MAX_MEM_MAPS");
        return -1;
    }

    struct mem_map *new_map = &ss->maps[ss->n_maps++];
    memcpy(new_map, map, sizeof(*map));
    return 0;
}

static int str_to_prot(const char *perms)
{
    int prot = 0;
    if (perms[0] == 'r')
        prot |= PROT_READ;
    if (perms[1] == 'w')
        prot |= PROT_WRITE;
    if (perms[2] == 'x')
        prot |= PROT_EXEC;
    return prot;
}

static int dump_fdstat(struct snapshot *ss);
static int get_fdstat(pid_t pid, int fd, void *data);
static int get_fdinfo(pid_t pid, int fd, struct fdstat *fdstat);
static int add_fdstat(struct snapshot *ss, struct fdstat *fdstat);

static int dump_kernel_status(struct snapshot *ss)
{
    return dump_fdstat(ss);
}

static int dump_fdstat(struct snapshot *ss)
{
    int ret;
    if ((ret = proc_traverse_fds(ss->pid, get_fdstat, (void *)ss)) < 0) {
        if (ret == -1)
            s2e_unix_err("proc_traverse_fds error");
        /* Otherwise, the error massage has been set by the handler. */
        return -1;
    }
    return 0;
}

static int get_fdstat(pid_t pid, int fd, void *data)
{
    struct fdstat fdstat;
    fdstat.fd = fd;
    if (proc_fstat(pid, fd, &fdstat.filestat) < 0)
        return 0; /* Continue to try next. */
    if (get_fdinfo(pid, fd, &fdstat) < 0)
        return 0; /* Continue to try next. */
    if (add_fdstat((struct snapshot *)data, &fdstat) < 0)
        return -2; /* Break. */
    return 0;
}

int get_fdinfo(pid_t pid, int fd, struct fdstat *fdstat)
{
    char link[MAXPATH];
    snprintf(link, ARRAY_LEN(link), "/proc/%d/fdinfo/%d", (int)pid, fd);

    FILE *fdinfo_fp = NULL;
    if ((fdinfo_fp = fopen(link, "r")) == NULL) {
        s2e_lib_err("Fail to open %s", link);
        return -1;
    }

    char line[MAXLINE];
    if (readline(fdinfo_fp, line, ARRAY_LEN(line)) == (char *)-1) {
        s2e_lib_err("readline error");
        goto errout;
    }
    if (sscanf(line, "pos: %ld", &fdstat->offset) != 1)
        goto errout;

    if (readline(fdinfo_fp, line, ARRAY_LEN(line)) == (char *)-1) {
        s2e_lib_err("readline error");
        goto errout;
    }
    if (sscanf(line, "flags: %o", &fdstat->oflag) != 1)
        goto errout;

    fclose(fdinfo_fp);
    return 0;

errout:
    if (fdinfo_fp)
        fclose(fdinfo_fp);
    return -1;
}

static int add_fdstat(struct snapshot *ss, struct fdstat *fdstat)
{
    if (ss->n_fds >= MAX_FDSTAT) {
        s2e_lib_err("exccess MAX_FDSTAT");
        return -1;
    }

    struct fdstat *new_fdstat = &ss->fdstat[ss->n_fds++];
    memcpy(new_fdstat, fdstat, sizeof(*fdstat));
    return 0;
}

void snapshot_show(struct snapshot *ss)
{
    printf("Program Status\n");
    struct user_regs_struct *r = &ss->regs;
    printf("rax: 0x%llx, rbx: 0x%llx, rcx: 0x%llx, rdx: 0x%llx\n",
           r->rax, r->rbx, r->rcx, r->rdx);
    printf("rsi: 0x%llx, rdi: 0x%llx, rbp: 0x%llx, rsp: 0x%llx\n",
           r->rsi, r->rdi, r->rbp, r->rsp);
    printf("r8: 0x%llx, r9: 0x%llx, r10: 0x%llx, r11: 0x%llx\n",
           r->r8, r->r9, r->r10, r->r11);
    printf("r12: 0x%llx, r13: 0x%llx, r14: 0x%llx, r15: 0x%llx\n",
           r->r12, r->r13, r->r14, r->r15);
    printf("orig_rax: 0x%llx, rip: 0x%llx, eflags: 0x%llx\n",
           r->orig_rax, r->rip, r->eflags);
    printf("fs.base: 0x%llx, gs.base: 0x%llx\n",
           r->fs_base, r->gs_base);
    printf("cs: 0x%llx, ss: 0x%llx, ds: 0x%llx, es: 0x%llx, fs: 0x%llx, gs: 0x%llx\n",
           r->cs, r->ss, r->ds, r->es, r->fs, r->gs);

    printf("\nMemory maps\n");
    struct mem_map *pmap = ss->maps;
    for (int i = 0; i < ss->n_maps; i++, pmap++) {
        printf("%p-%p %c%c%c\n", pmap->start, pmap->end,
               pmap->prot & PROT_READ ? 'r' : '-',
               pmap->prot & PROT_WRITE ? 'w' : '-',
               pmap->prot & PROT_EXEC ? 'x' : '-');
    }

    printf("\nFile Desciptors\n");
    struct fdstat *pfdstat = ss->fdstat;
    for (int i = 0; i < ss->n_fds; i++, pfdstat++) {
        printf("fd: %d, off: %ld, oflag: %o, type: %s\n",
               pfdstat->fd, (long)pfdstat->offset, pfdstat->oflag,
               file_type_str(pfdstat->filestat.st_mode));
    }
}

static int dump_opened_files(struct snapshot *ss);

static int dump_env(struct snapshot *ss)
{
    return dump_opened_files(ss);
}

static int dump_opened_files(struct snapshot *ss)
{
    char dump_path[MAXPATH];
    char src_path[MAXPATH];
    struct fdstat *pfdstat = ss->fdstat;
    for (int i = 0; i < ss->n_fds; i++, pfdstat++) {
        if (!S_ISREG(pfdstat->filestat.st_mode))
            continue;
        if (snprintf(dump_path, ARRAY_LEN(dump_path), "%s/%d",
                     ss->snapshot_dir, pfdstat->fd) >= ARRAY_LEN(dump_path)) {
            s2e_unix_err("exceed max path length");
            return -1;
        }
        snprintf(src_path, ARRAY_LEN(src_path), "/proc/%d/fd/%d", ss->pid, pfdstat->fd);
        if (copy_file(dump_path, src_path) < 0) {
            s2e_unix_err("copy '%s' to '%s' error", src_path, dump_path);
            return -1;
        }
    }
    return 0;
}

char *fetch_mem_map(pid_t pid, struct mem_map *map)
{
    char *data = malloc(map->end - map->start);
    if (!data) {
        s2e_unix_err("malloc error");
        return NULL;
    }

    if (ptrace_read(pid, map->start, data, map->end - map->start) < 0) {
        s2e_unix_err("ptrace read error: %p-%p", map->start, map->end);
        free(data);
        return NULL;
    }

    return data;
}
