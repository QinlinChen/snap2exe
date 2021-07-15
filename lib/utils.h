#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#define ARRAY_LEN(x)   (sizeof(x) / sizeof((x)[0]))

/* ptrace */
#define ptrace_traceme()                 ptrace(PTRACE_TRACEME, 0, NULL, NULL)
#define ptrace_attach(pid)               ptrace(PTRACE_ATTACH, pid, NULL, NULL)
#define ptrace_detach(pid)               ptrace(PTRACE_DETACH, pid, NULL, NULL)
#define ptrace_syscall(pid, sig)         ptrace(PTRACE_SYSCALL, pid, NULL, sig)
#define ptrace_setoptions(pid, options)  ptrace(PTRACE_SETOPTIONS, pid, NULL, options)
#define ptrace_getregs(pid, regs)        ptrace(PTRACE_GETREGS, pid, NULL, regs)
#define ptrace_setregs(pid, regs)        ptrace(PTRACE_SETREGS, pid, NULL, regs)
#define ptrace_getsiginfo(pid, siginfo)  ptrace(PTRACE_GETSIGINFO, pid, NULL, siginfo)
#define ptrace_peekdata(pid, addr)       ptrace(PTRACE_PEEKDATA, pid, addr, NULL)
#define ptrace_pokedata(pid, addr, data) ptrace(PTRACE_POKEDATA, pid, addr, (void *)data)

int ptrace_read(pid_t pid, void *addr, void *buf, size_t size);
int ptrace_write(pid_t pid, void *addr, void *buf, size_t size);

/* procfs */
int proc_traverse_fds(pid_t pid, int (*handle)(pid_t, int, void *), void *data);
int proc_fstat(pid_t pid, int fd, struct stat *buf);
int proc_fd_name(pid_t pid, int fd, char *buf, size_t size);
int proc_mem_read(pid_t pid, void *addr, char *buf, size_t size);
int proc_str_read(pid_t pid, void *addr, char *buf, size_t size);
int proc_cmdline_read(pid_t pid, char *buf, size_t size);

/* io */
char *readline(FILE *stream, char *buf, size_t size);
void close_all_fds(int (*whitelist)(int));
const char *file_type_str(mode_t mode);
int copy_regfile(const char *dst, const char *src);
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);

/* misc */
int detached_fork();
int find_in_array(int val, int arr[], int size);
int mkdir_p(const char *path, mode_t mode);
char *abspath(const char *path, char *buf, int size);

#endif /* _UTILS_H */
