#include <zerof/lib_utils.h>

#include <dlfcn.h>
#include <stdexcept>

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