#include "sys.h"
#include "utils.h"

#include <dirent.h>
#include <sys/wait.h>

/* ------------------------------------------------
 *                    ptrace
 * ------------------------------------------------ */

int ptrace_read(pid_t pid, void *addr, void *buf, size_t size)
{
    assert(size > 0);
    char *src = (char *)addr;
    char *dst = (char *)buf;
    errno = 0;

    char *aligned = src - (long)src % sizeof(long);
    if (aligned != src) {
        long data = ptrace_peekdata(pid, aligned);
        if (data == -1 && errno != 0)
            return -1;
        size_t lsize = src - aligned;
        size_t rsize = sizeof(long) - lsize;
        size_t minsize = (rsize < size ? rsize : size);
        memcpy(dst, (char *)&data + lsize, minsize);
        if (minsize == size)
            return 0;
        size -= minsize;
        src += minsize;
        dst += minsize;
    }
    
    while (size >= sizeof(long)) {
        long data = ptrace_peekdata(pid, src);
        if (data == -1 && errno != 0)
            return -1;
        *(long *)dst = data;
        size -= sizeof(long);
        dst += sizeof(long);
        src += sizeof(long);
    }

    if (size != 0) {
        long data = ptrace_peekdata(pid, src);
        if (data == -1 && errno != 0)
            return -1;
        memcpy(dst, &data, size);
    }

    return 0;
}

int ptrace_write(pid_t pid, void *addr, void *buf, size_t size)
{
    assert(size > 0);
    char *src = (char *)buf;
    char *dst = (char *)addr;
    errno = 0;

    char *aligned = dst - (long)dst % sizeof(long);
    if (aligned != dst) {
        long data = ptrace_peekdata(pid, aligned);
        if (data == -1 && errno != 0)
            return -1;
        size_t lsize = dst - aligned;
        size_t rsize = sizeof(long) - lsize;
        size_t minsize = (rsize < size ? rsize : size);
        memcpy((char *)&data + lsize, src, minsize);
        if (ptrace_pokedata(pid, aligned, data) == -1)
            return -1;
        if (minsize == size)
            return 0;
        size -= minsize;
        dst += minsize;
        src += minsize;
    }

    while (size >= sizeof(long)) {
        if (ptrace_pokedata(pid, dst, *(long *)src) == -1)
            return -1;
        size -= sizeof(long);
        dst += sizeof(long);
        src += sizeof(long);
    }

    if (size != 0) {
        long data = ptrace_peekdata(pid, dst);
        if (data == -1 && errno != 0)
            return -1;
        memcpy(&data, src, size);
        if (ptrace_pokedata(pid, dst, data) == -1)
            return -1;
    }

    return 0;
}

/* ------------------------------------------------
 *                      io
 * ------------------------------------------------ */

char *readline(FILE *stream, char *buf, size_t size)
{
    char *ret_val, *find;

    if (((ret_val = fgets(buf, size, stream)) == NULL) && ferror(stream))
        return (char *)-1;

    if (ret_val) {
        if ((find = strchr(buf, '\n')) != NULL) {
            *find = '\0';
        } else {
            while (1) {
                char eat = fgetc(stream);
                if (eat == '\n' || eat == EOF)
                    break;
            }
        }
    }
    return ret_val;
}

static int try_close_all_fds(int (*whitelist)(int))
{
    DIR *dir;
    struct dirent *ent;
    int fds[OPEN_MAX];
    int end = 0;

    if ((dir = opendir("/proc/self/fd")) == NULL)
        return -1;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* We shouldn't close fd during traversing directory entries because
           this will delete entries at the same time in this directory */
        if (end >= OPEN_MAX)
            break;
        fds[end++] = atoi(ent->d_name);
    }

    if (closedir(dir) == -1)
        return -1;

    for (int i = 0; i < end; ++i) {
        if (whitelist && whitelist(fds[i]))
            continue;
        close(fds[i]);
    }

    return 0;
}

static void force_close_all_fds(int (*whitelist)(int))
{
    for (int fd = 0; fd < 256; ++fd) {
        if (whitelist && whitelist(fd))
            continue;
        close(fd);
    }
}

void close_all_fds(int (*whitelist)(int))
{
    if (try_close_all_fds(whitelist) == -1)
        force_close_all_fds(whitelist);
}

/* ------------------------------------------------
 *                     procfs
 * ------------------------------------------------ */

int proc_fstat(pid_t pid, int fd, struct stat *buf)
{
    char file[MAXNAME];
    snprintf(file, ARRAY_LEN(file), "/proc/%d/fd/%d", (int)pid, fd);
    return stat(file, buf);
}

int proc_fd_name(pid_t pid, int fd, char *buf, size_t size)
{
    char link[MAXNAME];
    size_t len;

    snprintf(link, ARRAY_LEN(link), "/proc/%d/fd/%d", (int)pid, fd);
    if ((len = readlink(link, buf, size)) == -1) {
        buf[0] = '\0';
        return -1;
    }

    if (len >= size) {
        errno = EINVAL;
        buf[0] = '\0';
        return -1;
    }

    buf[len] = '\0';
    return len;
}

int proc_traverse_fds(pid_t pid, void (*handle)(pid_t, int))
{
    char dirname[MAXNAME];
    DIR *dir;
    struct dirent *ent;

    snprintf(dirname, ARRAY_LEN(dirname), "/proc/%d/fd", (int)pid);
    if ((dir = opendir(dirname)) == NULL)
        return -1;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        handle(pid, atoi(ent->d_name));
    }

    if (closedir(dir) == -1)
        return -1;

    return 0;
}

int proc_mem_read(pid_t pid, void *addr, char *buf, size_t size)
{
    char file[MAXNAME];
    int fd, nread;

    snprintf(file, ARRAY_LEN(file), "/proc/%d/mem", (int)pid);
    if ((fd = open(file, O_RDONLY)) < 0)
        return -1;

    if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1)
        goto close_and_err_out;

    if ((nread = read(fd, buf, size)) < 0)
        goto close_and_err_out;

    close(fd);
    return nread;

close_and_err_out:
    close(fd);
    return -1;
}

int proc_str_read(pid_t pid, void *addr, char *buf, size_t size)
{
    int nread;

    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    if ((nread = proc_mem_read(pid, addr, buf, size)) < 0)
        return -1;

    if (nread == (int)size)
        nread--;
    buf[nread] = '\0';
    return nread;
}

/* ------------------------------------------------
 *                     misc
 * ------------------------------------------------ */

int detached_fork()
{
    pid_t pid = fork();

    if (pid != 0) { /* Parent: the original process. */
        if (wait(NULL) != pid)
            return -1;
        return 1;
    }

    if ((pid = fork()) != 0)    /* Child */
        _exit(EXIT_SUCCESS);;

    return 0; /* Grandchild: a snapshot process. */
}

int find_in_array(int val, int arr[], int size)
{
    for (int i = 0; i < size; ++i)
        if (val == arr[i])
            return i;
    return -1;
}
