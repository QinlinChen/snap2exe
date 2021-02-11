#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core.h"
#include "error.h"
#include "undump.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
        app_errq("Usage: undump <core-file> <new-exec>");

    const char *core_file = argv[1];
    const char *new_exec = argv[2];

    struct core *c = load_core(core_file);
    if (!c)
        unix_errq("Fail to load core file \"%s\"", core_file);
    show_core_data(c);

    undumped_program *prog = undump(c);
    if (!prog)
        unix_errq("Fail to undump");

    int fd = open(new_exec, O_CREAT|O_RDWR, 0700);
    if (fd < 0)
        unix_errq("Fail to open new exec \"%s\"", new_exec);

    if (write_undumped(fd, prog) < 0)
        unix_errq("Fail to write new exec");

    return 0;
}
