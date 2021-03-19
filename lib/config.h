#ifndef _CONFIG_H
#define _CONFIG_H

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif /* OPEN_MAX */

#ifndef MAXLINE
#define MAXLINE 1024
#endif /* MAXLINE */

#ifndef MAXBUF
#define MAXBUF 1024
#endif /* MAXBUF */

#ifndef MAXPATH
#define MAXPATH 512
#endif /* MAXPATH */

struct s2e_config {
    char log_file[MAXPATH];
    int log_level;
    int sched_prob;
};

extern struct s2e_config config;

int load_config(const char *file);
int save_config(const char *file);

#endif // _CONFIG_H