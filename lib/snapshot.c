#include "sys.h"
#include "snapshot.h"

#include <regex.h>
#include <sys/mman.h>

#include "utils.h"

static int build_proc_maps(struct snapshot *ss);
static int add_proc_map(struct snapshot *ss, struct proc_map *map);
static char *substr(char *str, regmatch_t *match);
static long hexstr_to_long(const char *str);
static int str_to_prot(const char *perms);

int snapshot_build(struct snapshot *ss, pid_t pid)
{
    ss->pid = pid;
    ss->n_maps = 0;

    if (ptrace_getregs(pid, &ss->regs) != 0)
        return -1;

    if (build_proc_maps(ss) < 0)
        return -1;

    // TODO: build fs info.

    return 0;
}

/* Parse memory maps from /proc/[pid]/maps. */
static int build_proc_maps(struct snapshot *ss) {
    regex_t reg;
    int rc = regcomp(&reg,
                     "([0-9a-fA-F]+)\\-([0-9a-fA-f]+)\\s+([rwxps-]+)\\s+"
                     "[0-9a-fA-F]+\\s+[0-9a-fA-F]+:[0-9a-fA-F]+\\s+[0-9]+\\s+(.*)",
                     REG_EXTENDED);
    if (rc != 0) {
        char errbuf[MAXLINE];
        regerror(rc, &reg, errbuf, MAXLINE);
        printf("regex compilation failed: %s\n", errbuf);
        return -1;
    }

    FILE *fp;
    char filepath[MAXLINE];
    sprintf(filepath, "/proc/%d/maps", ss->pid);
    if ((fp = fopen(filepath, "r")) == NULL) {
        perror("Fail to open file");
        return -1;
    }

    char line[MAXLINE];
    regmatch_t match[5];
    while (readline(fp, line, MAXLINE) != NULL) {
        if (regexec(&reg, line, ARRAY_LEN(match), match, 0) == 0) {
            char *perms = substr(line, &match[3]);
            if (!perms) {
                printf("invalid format for perm???\n");
                goto errout;
            }
            if (strncmp(perms, "----", 4) == 0)
                continue; /* Maybe we can ignore this kind of maps. */

            struct proc_map map;
            map.start = (void *)hexstr_to_long(substr(line, &match[1]));
            map.end = (void *)hexstr_to_long(substr(line, &match[2]));
            map.prot = str_to_prot(perms);

            if (add_proc_map(ss, &map) < 0) {
                printf("exccess MAX_PROC_MAPS!");
                goto errout;
            }
        }
    }

    return fclose(fp);

errout:
    if (fp)
        fclose(fp);
    return -1;
}

static int add_proc_map(struct snapshot *ss, struct proc_map *map)
{
    if (ss->n_maps >= MAX_PROC_MAPS)
        return -1;

    struct proc_map *new_map = &ss->maps[ss->n_maps];
    ss->n_maps++;
    memcpy(new_map, map, sizeof(*map));
    return 0;
}

static char *substr(char *str, regmatch_t *match)
{
    assert(match->rm_eo >= match->rm_so);
    if (match->rm_so == match->rm_eo)
        return NULL;
    return str + match->rm_so;
}

static long hexstr_to_long(const char *str)
{
    long ret;
    sscanf(str, "%lx", &ret);
    return ret;
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
    printf("rip: 0x%llx, eflags: 0x%llx\n", r->rip, r->eflags);
    printf("fs.base: 0x%llx, gs.base: 0x%llx\n", r->fs_base, r->gs_base);
    printf("cs: 0x%llx, ss: 0x%llx, ds: 0x%llx, es: 0x%llx, fs: 0x%llx, gs: 0x%llx\n",
           r->cs, r->ss, r->ds, r->es, r->fs, r->gs);

    printf("\nMemory maps\n");
    struct proc_map *pmap = ss->maps;
    for (int i = 0; i < ss->n_maps; i++, pmap++) {
        printf("%p-%p %c%c%c\n", pmap->start, pmap->end,
               pmap->prot & PROT_READ ? 'r' : '-',
               pmap->prot & PROT_WRITE ? 'w' : '-',
               pmap->prot & PROT_EXEC ? 'x' : '-');
    }
}

char *alloc_read_proc_map(pid_t pid, struct proc_map *map)
{
    char *data = malloc(map->end - map->start);
    if (!data)
        return NULL;

    if (ptrace_read(pid, map->start, data, map->end - map->start) < 0) {
        free(data);
        return NULL;
    }

    return data;
}