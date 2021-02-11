#include "elfcommon.h"

#include <assert.h>

Elf64_Phdr *elf_get_program_headers(char *data)
{
    Elf64_Ehdr *header = elf_get_elf_header(data);
    assert(sizeof(Elf64_Phdr) == header->e_phentsize);
    return (Elf64_Phdr *)(data + header->e_phoff);
}

Elf64_Shdr *elf_get_section_headers(char *data)
{
    Elf64_Ehdr *header = elf_get_elf_header(data);
    assert(sizeof(Elf64_Shdr) == header->e_shentsize);
    return (Elf64_Shdr *)(data + header->e_shoff);
}

char *elf_get_section_strings(char *data)
{
    Elf64_Ehdr *header = elf_get_elf_header(data);
    Elf64_Shdr *sh = &elf_get_section_headers(data)[header->e_shstrndx];
    return data + sh->sh_offset;
}

char *elf_get_section_name(char *data, Elf64_Shdr *s)
{
    char *str = elf_get_section_strings(data);
    return str + s->sh_name;
}

const char *elf_seg_type_to_str(Elf64_Word type)
{
    switch (type) {
    case PT_NULL:
        return "NULL";
    case PT_LOAD:
        return "LOAD";
    case PT_DYNAMIC:
        return "DYNAMIC";
    case PT_INTERP:
        return "INTERP";
    case PT_NOTE:
        return "NOTE";
    case PT_SHLIB:
        return "SHLIB";
    case PT_PHDR:
        return "PHDR";
    case PT_TLS:
        return "TLS";
    case PT_LOOS:
        return "LOOS";
    case PT_HIOS:
        return "HIOS";
    case PT_LOPROC:
        return "LOPROC";
    case PT_HIPROC:
        return "HIPROC";
    case PT_GNU_EH_FRAME:
        return "GNU_EH_FRAME";
    case PT_GNU_STACK:
        return "GNU_STACK";
    case PT_GNU_RELRO:
        return "GNU_RELRO";
    default:
        return "UNDEFINED";
    }
}
