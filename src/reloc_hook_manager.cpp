#include <zerof/reloc_hook_manager.h>

#include <dlfcn.h>
#include <stdexcept>
#include <algorithm>
#include <elf.h>
#include <android/log.h>
#include <zerof/lib_utils.h>
#include <zerof/maps_helper.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG "RelocHookManager"

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD	4
#endif
#ifndef R_386_32
#define R_386_32 1
#endif
#ifndef R_386_JMP_SLOT
#define R_386_JMP_SLOT 7
#endif
#ifndef R_386_JMP_SLOT
#define R_386_GLOB_DAT 6
#endif

using namespace zerof;

reloc_hook_manager::lib_info::lib_info(void *base) : sym_helper(dlsym_helper::from_base(base)) {
    this->base = base;

    elf::Phdr *dynamic = lib_utils::find_dynamic(base);

    size_t dyn_data_count = (size_t) (dynamic->p_memsz / sizeof(elf::Dyn));
    elf::Dyn* dyn_data = (elf::Dyn*) ((size_t) base + dynamic->p_vaddr);

    for (int i = 0; i < dyn_data_count; i++) {
        if (dyn_data[i].d_tag == DT_NULL)
            break;
        switch (dyn_data[i].d_tag) {
            case DT_STRTAB:
                strtab = (const char*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_SYMTAB:
                symtab = (elf::Sym*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_REL:
                rel = (elf::Rel*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_RELSZ:
                relsz = (elf::Word) (dyn_data[i].d_un.d_val);
                break;
            case DT_RELA:
                rela = (elf::Rela*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_RELASZ:
                relasz = (elf::Word) (dyn_data[i].d_un.d_val);
                break;
            case DT_PLTREL:
                if ((elf::Word) (dyn_data[i].d_un.d_val) == DT_RELA)
                    pltrel_rela = true;
                break;
            case DT_JMPREL:
                pltrel = (elf::Rel*) ((size_t) base + dyn_data[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                pltrelsz = (elf::Word) (dyn_data[i].d_un.d_val);
                break;
            default:
                break;
        }
    }

    elf::Ehdr *header = (elf::Ehdr*) base;
    for (int i = 0; i < header->e_phnum; i++) {
        elf::Phdr &entry = *((elf::Phdr *)
                ((size_t) base + header->e_phoff + header->e_phentsize * i));
        if (entry.p_type == PT_GNU_RELRO) {
            relro = (void*) ((size_t) base + entry.p_vaddr);
            relrosize = entry.p_memsz;
        }
    }

    if (relro != nullptr) {
        auto page_size = sysconf(_SC_PAGE_SIZE);
        size_t pstart = (size_t) relro / page_size * page_size;
        size_t psize = (size_t) relro - pstart + relrosize;
        mprotect((void *) pstart, psize, PROT_READ | PROT_WRITE);
    }
}

const char* reloc_hook_manager::lib_info::get_symbol_name(elf::Word symbol_index) {
    return &strtab[symtab[symbol_index].st_name];
}

void reloc_hook_manager::lib_info::set_hook(
        const char *symbol_name, std::shared_ptr<reloc_hook_manager::hooked_symbol> hook) {
    set_hook(sym_helper.get_symbol_index(symbol_name), hook);
}

void reloc_hook_manager::lib_info::set_hook(
        elf::Word symbol_index, std::shared_ptr<reloc_hook_manager::hooked_symbol> hook) {
    hooked_symbols[symbol_index] = hook;
}


void reloc_hook_manager::lib_info::process_rel(elf::Addr *addr, elf::Word type, elf::Word sym) {
    auto found_symbol = hooked_symbols.find(sym);
    if (found_symbol == hooked_symbols.end())
        return;
    hooked_symbol& sym_info = *found_symbol->second;
    size_t replacement = (size_t) sym_info.original;
    size_t original = 0;

    if (sym_info.last_hook != nullptr && sym_info.last_hook->replacement != nullptr)
        replacement = (size_t) sym_info.last_hook->replacement;
    else if (replacement == 0)
        return;
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Found hook for %s at %p", &strtab[symtab[sym].st_name], addr);

    switch (type) {
#if defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#if defined(__aarch64__)
            case R_AARCH64_ABS64:
            case R_AARCH64_JUMP_SLOT:
            case R_AARCH64_GLOB_DAT:
#elif defined(__i386__)
            case R_386_32:
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
#elif defined(__arm__)
            case R_ARM_ABS32:
            case R_ARM_JUMP_SLOT:
            case R_ARM_GLOB_DAT:
#endif
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

void reloc_hook_manager::lib_info::apply_hooks(elf::Rel* rel, elf::Word relsz) {
    for (size_t i = 0; i < relsz / sizeof(elf::Rel); i++) {
#ifdef __LP64__
        elf::Word type = ELF64_R_TYPE(rel[i].r_info);
        elf::Word sym = ELF64_R_SYM(rel[i].r_info);
#else
        elf::Word type = ELF32_R_TYPE(rel[i].r_info);
        elf::Word sym = ELF32_R_SYM(rel[i].r_info);
#endif
        elf::Addr* addr = (elf::Addr*) ((size_t) base + rel[i].r_offset);

        process_rel(addr, type, sym);
    }
}

void reloc_hook_manager::lib_info::apply_hooks(elf::Rela* rela, elf::Word relasz) {
    for (size_t i = 0; i < relasz / sizeof(elf::Rela); i++) {
#ifdef __LP64__
        elf::Word type = ELF64_R_TYPE(rela[i].r_info);
        elf::Word sym = ELF64_R_SYM(rela[i].r_info);
#else
        elf::Word type = ELF32_R_TYPE(rela[i].r_info);
        elf::Word sym = ELF32_R_SYM(rela[i].r_info);
#endif
        elf::Addr* addr = (elf::Addr*) ((size_t) base + rela[i].r_offset);

        process_rel(addr, type, sym);
    }
}

void reloc_hook_manager::lib_info::apply_hooks() {
    apply_hooks(rel, relsz);
    apply_hooks(rela, relasz);
    if (pltrel_rela)
        apply_hooks((elf::Rela *) pltrel, pltrelsz);
    else
        apply_hooks(pltrel, pltrelsz);
}

void reloc_hook_manager::add_library(void *handle, const char *lookup_symbol) {
    if (libs.count(handle) > 0)
        return;
    auto& p = libs[handle] = std::unique_ptr<lib_info>(new lib_info(
            lib_utils::find_lib_base(handle, lookup_symbol)));

    elf::Phdr *dynamic = lib_utils::find_dynamic(p->base);

    auto dyn_data = lib_utils::read_original_dynamic(p->base);
    for (auto& dyn : dyn_data) {
        if (dyn.d_tag == DT_NULL)
            break;
        if (dyn.d_tag == DT_NEEDED) {
            void* dep = dlopen(&p->strtab[dyn.d_un.d_val], RTLD_NOLOAD);
            if (dep == nullptr)
                continue;
            p->dependencies.push_back(dep);
            dependents[dep].push_back(p.get());
            dlclose(dep);
        }
    }
}

void reloc_hook_manager::remove_library(void *handle) {
    auto p = libs.find(handle);
    if (p == libs.end())
        return;
    for (auto const& dep : p->second->dependencies)
        dependents[dep].erase(std::remove(dependents[dep].begin(), dependents[dep].end(),
                                          p->second.get()), dependents[dep].end());
    libs.erase(p);
}

reloc_hook_manager::hooked_symbol* reloc_hook_manager::get_or_create_hook_symbol(
        void *lib, elf::Word symbol_index) {
    auto lib_ir = libs.find(lib);
    if (lib_ir == libs.end())
        throw std::runtime_error("No such lib registered");
    lib_info* lib_i = lib_ir->second.get();
    auto& hook = hooked_symbols[{lib_i, symbol_index}];
    if (hook != nullptr)
        return hook.get();
    hook = std::shared_ptr<hooked_symbol>(new hooked_symbol);
    hook->lib = lib_i;
    hook->symbol_index = symbol_index;
    lib_i->set_hook(symbol_index, hook);
    auto name = lib_i->get_symbol_name(symbol_index);
    auto deps = dependents.find(lib);
    if (deps != dependents.end()) {
        for (lib_info *dep : deps->second)
            dep->set_hook(name, hook);
    }
    return hook.get();
}

reloc_hook_manager::hook_instance* reloc_hook_manager::create_hook(
        void *lib, elf::Word symbol_index, void *replacement, void **orig) {
    auto symbol = get_or_create_hook_symbol(lib, symbol_index);
    hook_instance* ret = new hook_instance;
    ret->symbol = symbol;
    ret->replacement = replacement;
    ret->orig = orig;
    if (ret->symbol->first_hook == nullptr) {
        ret->symbol->first_hook = ret;
    } else if (ret->symbol->last_hook != nullptr) {
        ret->parent = ret->symbol->last_hook;
        ret->parent->child = ret;
        *orig = ret->parent->replacement;
    }
    ret->symbol->last_hook = ret;
    return ret;
}

reloc_hook_manager::hook_instance* reloc_hook_manager::create_hook(
        void *lib, const char *symbol_name, void *replacement, void **orig) {
    auto lib_ir = libs.find(lib);
    if (lib_ir == libs.end())
        throw std::runtime_error("No such lib registered");
    elf::Word sym_index = lib_ir->second->sym_helper.get_symbol_index(symbol_name);
    if (sym_index == (elf::Word) -1)
        throw std::runtime_error((std::string("No such symbol: ") + symbol_name).c_str());
    return create_hook(lib, sym_index, replacement, orig);
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

void reloc_hook_manager::apply_hooks() {
    for (auto const& lib : libs)
        lib.second->apply_hooks();
}

void* reloc_hook_manager::resolve_symbol(void *lib, const char *symbol_name) {
    auto lib_ir = libs.find(lib);
    if (lib_ir == libs.end())
        throw std::runtime_error("No such lib registered");
    return lib_ir->second->sym_helper.dlsym(symbol_name);
}
