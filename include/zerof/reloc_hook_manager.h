#pragma once

#include <elf.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include "dlsym_helper.h"

namespace zerof {

class reloc_hook_manager {

private:
    struct hooked_symbol;
    class lib_info;
public:
    struct hook_instance {
    private:
        friend class reloc_hook_manager;
        hooked_symbol* symbol;
        hook_instance* parent = nullptr;
        hook_instance* child = nullptr;
        void* replacement;
        void** orig = nullptr;
    };

private:
    struct lib_symbol_pair {
        friend struct std::hash<lib_symbol_pair>;
        lib_info* lib;
        elf::Word symbol_index;

        bool operator==(lib_symbol_pair const& o) const {
            return lib == o.lib && symbol_index == o.symbol_index;
        }
    };
    struct lib_symbol_pair_hash {
        std::size_t operator()(const reloc_hook_manager::lib_symbol_pair &k) const {
            return (((size_t) (void*) k.lib) << 11) | k.symbol_index;
        }
    };
    struct hooked_symbol {
        lib_info* lib;
        elf::Word symbol_index;

        void* original = nullptr;
        hook_instance* first_hook = nullptr;
        hook_instance* last_hook = nullptr;
    };

    class lib_info {

    private:
        friend class reloc_hook_manager;

        void* base;

        const char* strtab = nullptr;
        elf::Sym* symtab = nullptr;
        elf::Rel* rel = nullptr;
        elf::Word relsz = 0;
        elf::Rela* rela = nullptr;
        elf::Word relasz = 0;
        elf::Rel* pltrel = nullptr;
        elf::Word pltrelsz = 0;
        bool pltrel_rela = false;
        void* relro = nullptr;
        elf::Word relrosize = 0;
        dlsym_helper sym_helper;

        std::unordered_map<elf::Word, std::shared_ptr<hooked_symbol>> hooked_symbols;

        std::vector<void*> dependencies;

        lib_info(void* base);


        void process_rel(elf::Addr *addr, elf::Word type, elf::Word sym);

        void apply_hooks(elf::Rel* rel, elf::Word relsz);

        void apply_hooks(elf::Rela* rel, elf::Word relsz);

    public:
        const char* get_symbol_name(elf::Word symbol_index);

        void set_hook(elf::Word symbol_index, std::shared_ptr<hooked_symbol> hook);

        void set_hook(const char* symbol_name, std::shared_ptr<hooked_symbol> hook);

        void apply_hooks();

    };

    std::unordered_map<void*, std::unique_ptr<lib_info>> libs;
    std::unordered_map<void*, std::vector<lib_info*>> dependents;
    std::unordered_map<lib_symbol_pair, std::shared_ptr<hooked_symbol>, lib_symbol_pair_hash>
            hooked_symbols;

    hooked_symbol* get_or_create_hook_symbol(void* lib, elf::Word symbol_index);

public:

    void add_library(void* handle, const char* lookup_symbol = "__bss_start");

    void remove_library(void* handle);

    void* resolve_symbol(void* lib, const char* symbol_name);

    hook_instance* create_hook(void* lib, elf::Word symbol_index, void* replacement, void** orig);

    hook_instance* create_hook(void* lib, const char* symbol_name, void* replacement, void** orig);

    void delete_hook(hook_instance* hook);

    void apply_hooks();

};

}