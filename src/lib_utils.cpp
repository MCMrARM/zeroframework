#include <zerof/lib_utils.h>

#include <dlfcn.h>
#include <stdexcept>
#include <zerof/maps_helper.h>

using namespace zerof;

void* lib_utils::find_lib_base(void *handle, const char *lookup_symbol) {
    void* sym = ::dlsym(handle, lookup_symbol);
    if (sym == nullptr)
        throw std::runtime_error("Failed to find the specified symbol in the library");
    Dl_info info;
    if (!dladdr(sym, &info) || info.dli_fbase == nullptr)
        throw std::runtime_error("Failed to find the specified symbol back (dladdr() failed)");
    return info.dli_fbase;
}

elf::Phdr* lib_utils::find_dynamic(void *base) {
    elf::Ehdr *header = (elf::Ehdr*) base;
    elf::Phdr *dynamic = nullptr;
    for (int i = 0; i < header->e_phnum; i++) {
        elf::Phdr &entry = *((elf::Phdr *)
                ((size_t) base + header->e_phoff + header->e_phentsize * i));
        if (entry.p_type == PT_DYNAMIC) {
            dynamic = &entry;
            break;
        }
    }
    if (dynamic == nullptr)
        throw std::runtime_error("Failed to find PT_DYNAMIC in the specified library");
    return dynamic;
}

std::vector<elf::Dyn> lib_utils::read_original_dynamic(void* base) {
    auto dynamic = find_dynamic(base);

    maps_helper maps;
    maps_helper::map* m;
    while ((m = maps.next()) != nullptr) {
        if ((size_t) base + dynamic->p_vaddr >= m->start && (size_t) base + dynamic->p_vaddr < m->end)
            break;
    }
    if (m == nullptr)
        throw std::runtime_error("Failed to find matching map");
    std::vector<elf::Dyn> dyn_data (dynamic->p_memsz / sizeof(elf::Dyn));
    FILE* fp = fopen(m->name, "rb");
    if (fp == nullptr)
        throw std::runtime_error("Failed to open file associated with the map");
    if (fseek(fp, dynamic->p_offset, SEEK_SET) != 0 ||
        fread(dyn_data.data(), sizeof(elf::Dyn), dyn_data.size(), fp) != dyn_data.size())
        throw std::runtime_error("Failed to read the dynamic section");
    fclose(fp);

    return dyn_data;
}