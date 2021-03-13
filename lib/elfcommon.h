#ifndef _ELFCOMMON_H
#define _ELFCOMMON_H

#include <elf.h>

#define elf_get_elf_header(data) ((Elf64_Ehdr*)(data))
Elf64_Phdr *elf_get_program_headers(char *data);
Elf64_Shdr *elf_get_section_headers(char *data);
char *elf_get_section_strings(char *data);
char *elf_get_section_name(char *data, Elf64_Shdr *s);
const char *elf_seg_type_to_str(Elf64_Word type);

#endif // _ELFCOMMON_H
