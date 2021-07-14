#include "sys.h"
#include "config.h"
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
 *                     procfs
 * ------------------------------------------------ */

int proc_traverse_fds(pid_t pid, int (*handle)(pid_t, int, void *), void *data)
{
    char dirname[MAXPATH];
    DIR *dir;
    struct dirent *ent;

    snprintf(dirname, sizeof(dirname), "/proc/%d/fd", (int)pid);
    if ((dir = opendir(dirname)) == NULL)
        return -1;

    int ret = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        ret = handle(pid, atoi(ent->d_name), data);
        if (ret < 0)
            break;
    }

    if (closedir(dir) == -1)
        return -1;

    return ret;
}

int proc_fstat(pid_t pid, int fd, struct stat *buf)
{
    char file[MAXPATH];
    snprintf(file, sizeof(file), "/proc/%d/fd/%d", (int)pid, fd);
    return stat(file, buf);
}

int proc_fd_name(pid_t pid, int fd, char *buf, size_t size)
{
    char link[MAXPATH];
    size_t len;

    snprintf(link, sizeof(link), "/proc/%d/fd/%d", (int)pid, fd);
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

int proc_mem_read(pid_t pid, void *addr, char *buf, size_t size)
{
    char file[MAXPATH];
    int fd, nread;

    snprintf(file, sizeof(file), "/proc/%d/mem", (int)pid);
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

int proc_cmdline_read(pid_t pid, char *buf, size_t size)
{
    char file[MAXPATH];
    snprintf(file, sizeof(file), "/proc/%d/cmdline", (int)pid);

    FILE *fp;
    if ((fp = fopen(file, "r")) == NULL)
        return -1;

    memset(buf, -1, size);
    if (readline(fp, buf, size) == (char *)-1)
        goto close_and_err_out;
    fclose(fp);

    /* Scan the buf reversely to the end of the cmdline. */
    int i = size - 1;
    while (buf[i] == (char)-1)
        --i;

    /* The format of cmdline is: "{cmd}\0{arg1}\0...\0{argn}\0\0".
       We first modify the second to last '\0' to '\n'. */
    if (--i >= 0 && buf[i] == '\0') {
        buf[i] = '\n';
    } 

    /* Then modify all '\0' to ' '. */
    for (--i; i >= 0; --i)
        if (buf[i] == '\0')
            buf[i] = ' ';
    return 0;

close_and_err_out:
    fclose(fp);
    return -1;
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

const char *file_type_str(mode_t mode)
{
    if (S_ISREG(mode))
        return "regular file";
    if (S_ISDIR(mode))
        return "directory";
    if (S_ISCHR(mode))
        return "character device";
    if (S_ISBLK(mode))
        return "block device";
    if (S_ISFIFO(mode))
        return "FIFO";
    if (S_ISLNK(mode))
        return "symbolic link";
    if (S_ISSOCK(mode))
        return "socket";
    return "unknown";
}

int copy_file(const char *dst_file, const char *src_file)
{
    int saved_errno;
    int src_fd = -1, dst_fd = -1;

    if ((src_fd = open(src_file, O_RDONLY)) < 0)
        return -1;

    if ((dst_fd = open(dst_file, O_WRONLY | O_CREAT | O_EXCL, 0644)) < 0)
        goto errout;

    char buf[4096];
    ssize_t nread;
    while ((nread = read(src_fd, buf, sizeof buf)) > 0) {
        char *out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = write(dst_fd, out_ptr, nread);
            if (nwritten >= 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else if (errno != EINTR) {
                goto errout;
            }
        } while (nread > 0);
    }

    if (nread < 0)
        goto errout;
    if (close(dst_fd) < 0) {
        dst_fd = -1;
        goto errout;
    }
    close(src_fd);
    return 0;

errout:
    saved_errno = errno;
    if (src_fd >= 0)
        close(src_fd);
    if (dst_fd >= 0)
        close(dst_fd);
    errno = saved_errno;
    return -1;
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;     /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;  /* byte offset, relative to l_whence */
    lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
    lock.l_len = len;       /* #bytes (0 means to EOF) */

    return fcntl(fd, cmd, &lock);
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

static int mkdir_p_rec(char *path, mode_t mode)
{
    if (path[0] == '\0')
        return 0;

    char *sep = strrchr(path, '/');
    if (sep) {
        *sep = '\0';
        if (mkdir_p_rec(path, mode) < 0)
            return -1;
        *sep = '/';
    }

    if (mkdir(path, 0777) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

int mkdir_p(const char *path, mode_t mode)
{
    assert(path);
    /* The input path is read-only but our algorithm needs a modifiable one,
       so we make a writable copy here. */
    char buf[MAXPATH];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, path, sizeof(buf) - 1);
    return mkdir_p_rec(buf, mode);
}

char *abspath(const char *path, char *buf, int size)
{
    if (!path || !buf)
        return NULL;
    if (path[0] == '/')
        return strncpy(buf, path, size);

    char cwd[MAXPATH];
    if (!getcwd(cwd, sizeof(cwd)))
        return NULL;
    if (snprintf(buf, size, "%s/%s", cwd, path) >= size)
        return NULL;
    return buf;
}