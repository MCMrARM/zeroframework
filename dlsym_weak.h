#pragma once

#include <elf.h>

class dlsym_weak_helper {

private:
    void* base;

    const char* strtab = nullptr;
    Elf32_Sym* symtab = nullptr;
    Elf32_Word hash_nbucket = 0;
    Elf32_Word hash_nchain = 0;
    Elf32_Word* hash_bucket = nullptr;
    Elf32_Word* hash_chain = nullptr;

    static unsigned int elfhash(const char* name);

public:
    dlsym_weak_helper(void* handle, const char* lookup_symbol = "__bss_start");

    void* dlsym(const char* symbol);

};
