#include "reloc_hook_manager.h"

#include <dlfcn.h>
#include <stdexcept>
#include <elf.h>
#include <android/log.h>

#define TAG "RelocHookManager"

reloc_hook_manager::reloc_hook_manager(void *handle, const char *lookup_symbol) {
    void* sym = ::dlsym(handle, lookup_symbol);
    if (sym == nullptr)
        throw std::runtime_error("Failed to find the specified symbol in the library");
    Dl_info info;
    if (!dladdr(sym, &info) || info.dli_fbase == nullptr)
        throw std::runtime_error("Failed to find the specified symbol back (dladdr() failed)");
    base = info.dli_fbase;

    // find the dynamic section
    Elf32_Ehdr *header = (Elf32_Ehdr*) base;
    Elf32_Phdr *dynamic = nullptr;
    for (int i = 0; i < header->e_phnum; i++) {
        Elf32_Phdr &entry = *((Elf32_Phdr *)
                ((size_t) base + header->e_phoff + header->e_phentsize * i));
        if (entry.p_type == PT_DYNAMIC) {
            dynamic = &entry;
            break;
        }
    }
    if (dynamic == nullptr)
        throw std::runtime_error("Failed to find PT_DYNAMIC in the specified library");


    size_t dyn_data_count = (size_t) (dynamic->p_memsz / sizeof(Elf32_Dyn));
    Elf32_Dyn* dyn_data = (Elf32_Dyn*) ((size_t) base + dynamic->p_vaddr);

    for (int i = 0; i < dyn_data_count; i++) {
        if (dyn_data[i].d_tag == DT_NULL)
            break;
        switch (dyn_data[i].d_tag) {
            case DT_REL:
                rel = (Elf32_Rel*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_RELSZ:
                relsz = (Elf32_Word) (dyn_data[i].d_un.d_val);
                break;
            case DT_PLTREL:
                pltrel = (Elf32_Rel*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                pltrelsz = (Elf32_Word) (dyn_data[i].d_un.d_val);
                break;
            default:
                break;
        }
    }
}

reloc_hook_manager::hook_instance* reloc_hook_manager::create_hook(
        Elf32_Word symbol_index, void *replacement, void **orig) {
    hook_instance* ret = new hook_instance;
    auto found_symbol = hooked_symbols.find(symbol_index);
    if (found_symbol != hooked_symbols.end()) {
        ret->symbol = found_symbol->second.get();
    } else {
        std::unique_ptr<hooked_symbol> info (new hooked_symbol);
        ret->symbol = info.get();
        hooked_symbols.insert({symbol_index, std::move(info)});
    }
    if (ret->symbol->first_hook == nullptr) {
        ret->symbol->first_hook = ret;
    } else if (ret->symbol->last_hook != nullptr) {
        ret->parent = ret->symbol->last_hook;
        ret->parent->child = ret;
        ret->symbol->last_hook = ret;
        *orig = ret->parent->replacement;
    }
    return ret;
}

void reloc_hook_manager::delete_hook(hook_instance *hook) {
    if (hook->child) {
        hook->child->parent = hook->parent;
        if (hook->parent)
            *hook->child->orig = hook->parent->replacement;
        else
            *hook->child->orig = hook->symbol->original;
    }
    if (hook->parent)
        hook->parent->child = hook->child;
    if (hook->symbol->first_hook == hook)
        hook->symbol->first_hook = hook->child;
    if (hook->symbol->last_hook == hook)
        hook->symbol->last_hook = hook->parent;
    delete hook;
}

void reloc_hook_manager::apply_hooks(Elf32_Rel* rel, Elf32_Word relsz) {
    for (size_t i = 0; i < relsz / sizeof(Elf32_Dyn); i++) {
        Elf32_Word type = ELF32_R_TYPE(rel[i].r_info);
        Elf32_Word sym = ELF32_R_SYM(rel[i].r_info);
        Elf32_Word* addr = (Elf32_Word*) ((size_t) base + rel[i].r_offset);
        auto found_symbol = hooked_symbols.find(sym);
        if (found_symbol == hooked_symbols.end())
            continue;
        hooked_symbol& sym_info = *found_symbol->second;
        size_t replacement = (size_t) sym_info.original;
        size_t original = 0;

        if (sym_info.last_hook != nullptr && sym_info.last_hook->replacement != nullptr)
            replacement = (size_t) sym_info.last_hook->replacement;
        else if (replacement == 0)
            continue;

        switch (type) {
#ifndef __i386__
        case R_ARM_JUMP_SLOT:
            original = (size_t) *addr;
            (size_t&) *addr = replacement;
            break;
#endif
        default:
            __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown relocation type: %x", type);
        }

        if (original && sym_info.original == nullptr) {
            sym_info.original = (void *) original;
            if (sym_info.first_hook)
                *sym_info.first_hook->orig = (void *) original;
        }
    }
}

void reloc_hook_manager::apply_hooks() {
    apply_hooks(rel, relsz);
    apply_hooks(pltrel, pltrelsz);
}