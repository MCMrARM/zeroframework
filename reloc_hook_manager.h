#pragma once

#include <elf.h>
#include <string>
#include <unordered_map>
#include <vector>

class reloc_hook_manager {

private:
    struct hooked_symbol;
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
    void* base;

    Elf32_Rel* rel = nullptr;
    Elf32_Word relsz = 0;
    Elf32_Rel* pltrel = nullptr;
    Elf32_Word pltrelsz = 0;

    struct hooked_symbol {
        void* original = nullptr;
        hook_instance* first_hook = nullptr;
        hook_instance* last_hook = nullptr;
    };

    std::unordered_map<Elf32_Word, std::unique_ptr<hooked_symbol>> hooked_symbols;

    void apply_hooks(Elf32_Rel* rel, Elf32_Word relsz);

public:
    reloc_hook_manager(void* handle, const char* lookup_symbol = "__bss_start");

    hook_instance* create_hook(Elf32_Word symbol_index, void* replacement, void** orig);

    void delete_hook(hook_instance* hook);

    void apply_hooks();

};
