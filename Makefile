ifeq ($(PREFIX),)
	PREFIX := $(HOME)/local/snap2exe
endif
override PREFIX := $(abspath $(PREFIX))

build_dir := ./build

# define project target, includes, and sources
snap2exe_lib          := $(build_dir)/libsnap2exe.a
snap2exe_lib_srcs     := $(shell find lib/ -name "*.c")
snap2exe_bin          := $(build_dir)/snap2exe
snap2exe_bin_srcs     := $(shell find src/ -name "*.c")
snap2exe_include_dir := ./include

# common compile options
CC     ?= gcc
CFLAGS += -O2 -g -Wall -I$(snap2exe_include_dir)
LD     := $(CC)
AR     := ar

# intermediate files
obj_dir  := $(build_dir)/obj
lib_objs := $(snap2exe_lib_srcs:%.c=$(obj_dir)/%.o)
bin_objs := $(snap2exe_bin_srcs:%.c=$(obj_dir)/%.o)

$(snap2exe_bin): $(bin_objs) $(snap2exe_lib)
	@echo + LD $@
	@$(LD) -o $@ $^

$(snap2exe_lib): $(lib_objs)
	@echo + AR $@
	@$(AR) rcs $@ $^

$(obj_dir)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -fPIC -MMD -c -o $@ $<

-include $(objs:.o/.d)

.PHONY: clean install test example

clean:
	-rm -rf $(build_dir)

install: $(snap2exe_lib) $(snap2exe_bin)
	@install -D -m 755 -t $(PREFIX)/bin $(snap2exe_bin)
	@install -D -m 755 -t $(PREFIX)/lib $(snap2exe_lib)
	@(cd $(snap2exe_include_dir) && find . -type f -exec install -D -m 644 {} $(PREFIX)/include/{} \;)

test-tool: test/test-tool.c $(snap2exe_bin)
	$(CC) $(CFLAGS) -o $@ test/test-tool.c

test-ckpt: test/test-ckpt.c include/snap2exe/*.h $(snap2exe_lib)
	$(CC) $(CFLAGS) -o $@ test/test-ckpt.c $(snap2exe_lib)

test-calc: test/test-calc.c include/snap2exe/*.h $(snap2exe_lib)
	$(CC) $(CFLAGS) -o $@ test/test-calc.c $(snap2exe_lib)

test: test-tool test-ckpt test-calc

