#pragma once

#include "elf.h"

namespace zerof {

class dlsym_helper {

private:
    void *base;

    const char *strtab = nullptr;
    elf::Sym *symtab = nullptr;
    elf::Word hash_nbucket = 0;
    elf::Word hash_nchain = 0;
    elf::Word *hash_bucket = nullptr;
    elf::Word *hash_chain = nullptr;

    static unsigned int elfhash(const char *name);

    dlsym_helper(void *base);

public:
    static dlsym_helper from_handle(void *handle, const char *lookup_symbol = "__bss_start");

    static dlsym_helper from_base(void *base);

    elf::Word get_symbol_index(const char *symbol);

    void *dlsym(const char *symbol);

};

}