#ifndef _SNAP2EXE_SYS_H
#define _SNAP2EXE_SYS_H

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <errno.h>
#include <assert.h>

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif /* OPEN_MAX */

#ifndef MAXLINE
#define MAXLINE 1024
#endif /* MAXLINE */

#ifndef MAXBUF
#define MAXBUF 1024
#endif /* MAXBUF */

#ifndef MAXNAME
#define MAXNAME 1024
#endif /* MAXNAME */

#endif /* _SNAP2EXE_SYS_H */