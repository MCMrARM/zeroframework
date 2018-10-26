#include "dlsym_weak.h"

#include <dlfcn.h>
#include <stdexcept>
#include <elf.h>
#include "lib_utils.h"

dlsym_weak_helper::dlsym_weak_helper(void *base) {
    this->base = base;

    Elf32_Phdr *dynamic = lib_utils::find_dynamic(base);

    size_t dyn_data_count = (size_t) (dynamic->p_memsz / sizeof(Elf32_Dyn));
    Elf32_Dyn* dyn_data = (Elf32_Dyn*) ((size_t) base + dynamic->p_vaddr);

    for (int i = 0; i < dyn_data_count; i++) {
        if (dyn_data[i].d_tag == DT_NULL)
            break;
        if (dyn_data[i].d_tag == DT_HASH) {
            Elf32_Word* data = (Elf32_Word*) ((size_t) base + dyn_data[i].d_un.d_ptr);
            hash_nbucket = data[0];
            hash_nchain = data[1];
            hash_bucket = &data[2];
            hash_chain = &data[2 + hash_nbucket];
        }
        if (dyn_data[i].d_tag == DT_STRTAB) {
            strtab = (const char*) ((size_t) base + dyn_data[i].d_un.d_ptr);
        }
        if (dyn_data[i].d_tag == DT_SYMTAB) {
            symtab = (Elf32_Sym*) ((size_t) base + dyn_data[i].d_un.d_ptr);
        }
    }
}

dlsym_weak_helper dlsym_weak_helper::from_base(void *base) {
    return dlsym_weak_helper(base);
}

dlsym_weak_helper dlsym_weak_helper::from_handle(void *handle, const char *lookup_symbol) {
    return dlsym_weak_helper(lib_utils::find_lib_base(handle, lookup_symbol));
}

unsigned int dlsym_weak_helper::elfhash(const char *symbol) {
    unsigned int h = 0;
    for ( ; *symbol; ++symbol) {
        h = (h << 4) + (unsigned char) *symbol;
        unsigned int high = h & 0xF0000000;
        if (high)
            h ^= high >> 24;
        h &= ~high;
    }
    return h;
}

Elf32_Word dlsym_weak_helper::get_symbol_index(const char *symbol) {
    unsigned int hash = elfhash(symbol) % hash_nbucket;
    for (Elf32_Word index = hash_bucket[hash]; index != 0; index = hash_chain[index]) {
        if (strcmp(&strtab[symtab[index].st_name], symbol) == 0)
            return index;
    }
    return (Elf32_Word) -1;
}

void* dlsym_weak_helper::dlsym(const char *symbol) {
    unsigned int hash = elfhash(symbol) % hash_nbucket;
    for (Elf32_Word index = hash_bucket[hash]; index != 0; index = hash_chain[index]) {
        if (strcmp(&strtab[symtab[index].st_name], symbol) == 0)
            return (void*) ((size_t) base + symtab[index].st_value);
    }
    return nullptr;
}