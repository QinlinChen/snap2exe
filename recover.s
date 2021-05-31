.global _start
.text
_start:
    # arch_prctl(ARCH_SET_FS, fs_base)
    movq $158, %rax
    movq $0x1002, %rdi
    movq $0x1234567890, %rsi
.data
file1:
    .asciz "filename"
.text
reopen:
    # fd = open(file1, oflag， 0)
    movq $2, %rax
    movq $file1, %rdi
    movq $0x1234567890, %rsi
    movq $0, %rdx
    syscall
    cmpl $0, %eax
    jl errout
    cmpl $0x1234567890, %eax
    je reseek
    pushq %rax
    pushq %rax
    # dup2(fd, old_fd)
    movq %rax, %rdi
    movq $0x1234567890, %rsi
    movq $33, %rax
    syscall
    # close(fd)
    popq %rax
    movq %rax, %rdi
    movq $3, %rax
    syscall
    popq %rax
reseek:
    # seek(fd, offset, SEEK_SET)
    movq %rax, %rdi
    movq $0x1234567890, %rsi
    movq $0, %rdx
    movq $8, %rax
    syscall
errout:
    movq $0x1234567890, %rax
    movq $0x1234567890, %rdi
    movq $0x1234567890, %rsi
    movq $0x1234567890, %rdx

.text
    movq $0x1234567890, %rbx
    movq $0x1234567890, %rcx
    movq $0x1234567890, %rdx
    movq $0x1234567890, %rsp
    movq $0x1234567890, %rbp
    movq $0x1234567890, %rsi
    movq $0x1234567890, %rdi
    movq $0x1234567890, %r8
    movq $0x1234567890, %r9
    movq $0x1234567890, %r10
    movq $0x1234567890, %r11
    movq $0x1234567890, %r12
    movq $0x1234567890, %r13
    movq $0x1234567890, %r14
    movq $0x1234567890, %r15

    # Recover eflags.
    movq $0x1234567890, %rax
    pushq %rax
    popfq

    # Push rip for return
    movq $0x1234567890, %rax
    pushq %rax

    movq $0x1234567890, %rax
    retq
