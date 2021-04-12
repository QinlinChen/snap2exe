#ifndef _SNAP2EXE_SNAP2EXE_H
#define _SNAP2EXE_SNAP2EXE_H

#include <sys/types.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* snap2exe.c */
int snap2exe(pid_t pid, const char *new_exec);

/* error.c */
char *s2e_errmsg(char *buf, size_t len);
void s2e_set_errmsg(int errnoflag, int error, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#define s2e_unix_err(fmt, ...) \
    do { \
        s2e_set_errmsg(1, errno, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#define s2e_posix_err(error, fmt, ...) \
    do { \
        s2e_set_errmsg(1, (error), "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#define s2e_lib_err(fmt, ...) \
    do { \
        s2e_set_errmsg(0, 0, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#endif // _SNAP2EXE_SNAP2EXE_H
