build_dir      := ./build
install_prefix := $$HOME/snap2exe

# define project target, includes, and sources
snap2exe_bin          := $(build_dir)/snap2exe
snap2exe_include_dirs := ./include
snap2exe_srcs         := $(shell find src/ lib/ -name "*.c")

# compile options
CC     := gcc
CFLAGS += -O2 -g -Wall $(addprefix -I, $(snap2exe_include_dirs))
LD     := $(CC)

# intermediate files
obj_dir := $(build_dir)/obj
objs    := $(snap2exe_srcs:%.c=$(obj_dir)/%.o)

$(snap2exe_bin): $(objs)
	@echo + LD $@
	@$(LD) -o $@ $^

$(obj_dir)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MMD -c -o $@ $<

-include $(objs:.o/.d)

.PHONY: clean install test example

clean:
	-rm -rf $(build_dir)

install: $(snap2exe_bin)
	@mkdir -p $(install_prefix)
	@mkdir -p $(install_prefix)/bin
	@cp $(snap2exe_bin) $(install_prefix)/bin
	@for include_dir in $(snap2exe_include_dirs); do \
		cp -r $$include_dir $(install_prefix); \
	done

test: test.c
	$(CC) -o $@ $^ -no-pie -static -g

example: example.c lib/*.c include/snap2exe.h
	$(CC) -o $@ -Wall -I ./include example.c lib/*.c
