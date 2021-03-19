#include "sys.h"
#include "config.h"

#include <ctype.h>

#include "log.h"
#include "utils.h"

/* Default configures. */
struct s2e_config config = {
    .log_file = "/tmp/s2e.log",
    .log_level = LEVEL_ERROR,
    .sched_prob = 100,
};

static char *eat_space(char *p)
{
    while (*p != '\0' && isspace(*p))
        p++;
    return p;
}

static int parse_line(char *line, char **key, char **val)
{
    char *p = eat_space(line);
    if (*p == '\0' || *p == '#')
        return 0; /* Empty lines and comment lines */

    /* Parse key. */
    *key = p;
    if ((p = strchr(p, ':')) == NULL || *key == p)
        return -1;
    *p++ = '\0';

    /* Parse value. */
    p = eat_space(p);
    if (*p == '\0')
        return -2;
    *val = p;
    while (*p != '\0' && !isspace(*p))
        p++;
    *p = '\0';

    return 1;
}

static int config_set(const char *key, const char *val)
{
    int log_level, sched_prob;

    if (!strcmp(key, "log_file")) {
        strcpy(config.log_file, val);
        return 0;
    }
    if (!strcmp(key, "log_level")) {
        log_level = str_to_level(val);
        if (log_level == -1)
            return -1;
        config.log_level = log_level;
        return 0;
    }
    if (!strcmp(key, "sched_prob")) {
        if (sscanf(val, "%d", &sched_prob) != 1)
            return -1;
        config.sched_prob = sched_prob;
        return 0;
    }
    return -1;
}

int load_config(const char *file)
{
    FILE *fp;
    char line[MAXLINE];

    if ((fp = fopen(file, "r")) == NULL)
        return -1;

    /* Read and parse lines.*/
    while (1) {
        char *ret, *key, *val;
        int parse_ok;

        ret = readline(fp, line, ARRAY_LEN(line));
        if (ret == (char *)-1)
            goto close_and_err_out;
        if (!ret)
            break;

        parse_ok = parse_line(line, &key, &val);
        if (parse_ok == 1) {
            if (config_set(key, val) != 0)
                log_error("Fail to set configure %s=%s", key, val);
        } else if (parse_ok == -1) {
            log_error("parse key error: the line is \"%s\"", line);
        } else if (parse_ok == -2) {
            log_error("parse value error: the key is \"%s\"", key);
        }
    }

    fclose(fp);
    return 0;

close_and_err_out:
    fclose(fp);
    return -1;
}

int save_config(const char *file)
{
    FILE *fp;

    if ((fp = fopen(file, "w")) == NULL)
        return -1;

    fprintf(fp, "log_file: %s\n", config.log_file);
    fprintf(fp, "log_level: %s\n", level_to_str(config.log_level));
    fprintf(fp, "sched_prob: %d\n", config.sched_prob);

    fclose(fp);
    return 0;
}