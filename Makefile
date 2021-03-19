build_dir      := ./build
install_prefix := $$HOME/snap2exe

# define project target, includes, and sources
snap2exe_lib          := $(build_dir)/libsnap2exe.a
snap2exe_lib_srcs     := $(shell find lib/ -name "*.c")
snap2exe_bin          := $(build_dir)/snap2exe
snap2exe_bin_srcs     := $(shell find src/ -name "*.c")
snap2exe_include_dirs := ./include

# common compile options
CC     := gcc
CFLAGS += -O2 -g -Wall $(addprefix -I, $(snap2exe_include_dirs))
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
	@$(CC) $(CFLAGS) -MMD -c -o $@ $<

-include $(objs:.o/.d)

.PHONY: clean install test example

clean:
	-rm -rf $(build_dir)

install: $(snap2exe_lib) $(snap2exe_bin)
	@mkdir -p $(install_prefix)
	@mkdir -p $(install_prefix)/bin
	@cp $(snap2exe_bin) $(install_prefix)/bin
	@mkdir -p $(install_prefix)/lib
	@cp $(snap2exe_lib) $(install_prefix)/lib
	@for include_dir in $(snap2exe_include_dirs); do \
		cp -r $$include_dir $(install_prefix); \
	done

test-tool: test/test-tool.c $(snap2exe_bin)
	$(CC) $(CFLAGS) -o $@ test/test-tool.c

test-ckpt: test/test-ckpt.c include/snap2exe/*.h $(snap2exe_lib)
	$(CC) $(CFLAGS) -o $@ test/test-ckpt.c $(snap2exe_lib)

test-calc: test/test-calc.c include/snap2exe/*.h $(snap2exe_lib)
	$(CC) $(CFLAGS) -o $@ test/test-calc.c $(snap2exe_lib)

test: test-tool test-ckpt test-calc

