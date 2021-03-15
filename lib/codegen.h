#ifndef _CODEGEN_H
#define _CODEGEN_H

#include <stdint.h>
#include <string.h>

#define INS_STR(buf, str) \
    do { \
        strcpy(buf, str); \
        (buf) += strlen(str) + 1; \
    } while (0)

#define _INS_VAL(buf, val, size) \
    do { \
        uint##size##_t tmp_var = (val); \
        memcpy(buf, &tmp_var, sizeof(tmp_var)); \
        (buf) += sizeof(tmp_var); \
    } while (0)

#define INS_B(buf, val) _INS_VAL(buf, val, 8)
#define INS_W(buf, val) _INS_VAL(buf, val, 16)
#define INS_L(buf, val) _INS_VAL(buf, val, 32)
#define INS_Q(buf, val) _INS_VAL(buf, val, 64)

#define INS_MOV_I2AX(buf, imm) \
    do { INS_W(buf, 0xb866); INS_W(buf, imm); } while (0)

#define INS_MOV_AX2ES(buf) INS_W(buf, 0xc08e)
#define INS_MOV_AX2CS(buf) INS_W(buf, 0xc88e)
#define INS_MOV_AX2SS(buf) INS_W(buf, 0xd08e)
#define INS_MOV_AX2DS(buf) INS_W(buf, 0xd88e)
#define INS_MOV_AX2FS(buf) INS_W(buf, 0xe08e)
#define INS_MOV_AX2GS(buf) INS_W(buf, 0xe88e)

#define _INS_OPW_IQ(buf, op, imm) \
    do { INS_W(buf, op); INS_Q(buf, imm); } while (0)

#define INS_MOV_I2RAX(buf, imm) _INS_OPW_IQ(buf, 0xb848, imm)
#define INS_MOV_I2RCX(buf, imm) _INS_OPW_IQ(buf, 0xb948, imm)
#define INS_MOV_I2RDX(buf, imm) _INS_OPW_IQ(buf, 0xba48, imm)
#define INS_MOV_I2RBX(buf, imm) _INS_OPW_IQ(buf, 0xbb48, imm)
#define INS_MOV_I2RSP(buf, imm) _INS_OPW_IQ(buf, 0xbc48, imm)
#define INS_MOV_I2RBP(buf, imm) _INS_OPW_IQ(buf, 0xbd48, imm)
#define INS_MOV_I2RSI(buf, imm) _INS_OPW_IQ(buf, 0xbe48, imm)
#define INS_MOV_I2RDI(buf, imm) _INS_OPW_IQ(buf, 0xbf48, imm)
#define INS_MOV_I2R8(buf, imm)  _INS_OPW_IQ(buf, 0xb849, imm)
#define INS_MOV_I2R9(buf, imm)  _INS_OPW_IQ(buf, 0xb949, imm)
#define INS_MOV_I2R10(buf, imm) _INS_OPW_IQ(buf, 0xba49, imm)
#define INS_MOV_I2R11(buf, imm) _INS_OPW_IQ(buf, 0xbb49, imm)
#define INS_MOV_I2R12(buf, imm) _INS_OPW_IQ(buf, 0xbc49, imm)
#define INS_MOV_I2R13(buf, imm) _INS_OPW_IQ(buf, 0xbd49, imm)
#define INS_MOV_I2R14(buf, imm) _INS_OPW_IQ(buf, 0xbe49, imm)
#define INS_MOV_I2R15(buf, imm) _INS_OPW_IQ(buf, 0xbf49, imm)

#define INS_PUSH_RAX(buf)  INS_B(buf, 0x50)
#define INS_POP_RAX(buf)   INS_B(buf, 0x58)
#define INS_POPF(buf)      INS_B(buf, 0x9d)
#define INS_RET(buf)       INS_B(buf, 0xc3)

#define INS_CMPL_EAX(buf, imm) \
    do { INS_B(buf, 0x3d); INS_L(buf, imm); } while (0)

#define INS_JL(buf, rel) \
    do { INS_B(buf, 0x7c); INS_B(buf, rel); } while (0)

#define INS_JE(buf, rel) \
    do { INS_B(buf, 0x74); INS_B(buf, rel); } while (0)

/* x86_64-linux system calling convention:
     sysnum: %rax
     arg1-6: %rdi, %rsi, %rdx, %r10, %r8 and %r9. */

#define INS_SYSCALL(buf)   INS_W(buf, 0x050f)

#define INS_SYSCALL0(buf, sysnum) \
    do { \
        INS_MOV_I2RAX(buf, sysnum); INS_SYSCALL(buf); \
    } while (0)

#define INS_SYSCALL1(buf, sysnum, arg1) \
    do { \
        INS_MOV_I2RDI(buf, arg1); INS_SYSCALL0(buf, sysnum); \
    } while (0)

#define INS_SYSCALL2(buf, sysnum, arg1, arg2) \
    do { \
        INS_MOV_I2RSI(buf, arg2); INS_SYSCALL1(buf, sysnum, arg1); \
    } while (0)

#define INS_SYSCALL3(buf, sysnum, arg1, arg2, arg3) \
    do { \
        INS_MOV_I2RDX(buf, arg3); INS_SYSCALL2(buf, sysnum, arg1, arg2); \
    } while (0)

#endif // _CODEGEN_H