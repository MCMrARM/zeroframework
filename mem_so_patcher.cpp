#include "mem_so_patcher.h"
#include "maps_helper.h"

#include <sys/mman.h>
#include <sys/sysconf.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>

#define TAG "MemSoPatcher"

bool mem_so_patcher::linker_hooked = false;
std::map<std::string, mem_so_patcher::lib_info> mem_so_patcher::libs;
std::vector<code_region> mem_so_patcher::code_regions;

static unsigned char pattern_syscall_05_open[]    = { 0x07, 0xC0, 0xA0, 0xE1, 0x05, 0x70, 0xA0, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0x0C, 0x70, 0xA0, 0xE1 };
static unsigned char pattern_syscall_142_openat[] = { 0x07, 0xC0, 0xA0, 0xE1, 0x42, 0x71, 0x00, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0x0C, 0x70, 0xA0, 0xE1 };
static unsigned char pattern_syscall_C0_mmap2[]   = { 0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0x00, 0x2D, 0xE9, 0x70, 0x00, 0x9C, 0xE8, 0xC0, 0x70, 0xA0, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0xF0, 0x00, 0xBD, 0xE8 };

void code_region::free() {
    if (start != nullptr)
        munmap(start, (size_t) end - (size_t) start);
    release();
}

code_region code_region::alloc(size_t min_size) {
    int page_size = sysconf(_SC_PAGE_SIZE);
    size_t size = (min_size + page_size - 1) / page_size * page_size;
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    return code_region(ptr, size);
}

void* code_region::take(size_t size) {
    if (current == nullptr || (size_t) current + size > (size_t) end)
        return nullptr;
    void* ret = current;
    current = (void*) ((size_t) current + size);
    return ret;
}

void* mem_so_patcher::allocate_trampoline(size_t size) {
    if (!code_regions.empty()) {
        void* ret = code_regions.back().take(size);
        if (ret != nullptr)
            return ret;
    }
    // create a new region
    code_regions.push_back(code_region::alloc(size));
    return code_regions.back().take(size);

}

void mem_so_patcher::hook_syscall(void *ptr, void *hook, void **orig) {
    bool thumb = (((size_t) ptr) & 1) != 0;
    unsigned char* data = (unsigned char*) ptr;
    if (thumb) { // thumb is not currently used
        abort();
    }

    unsigned char pc_ldr_instr[] = {0x04, 0xF0, 0x1F, 0xE5}; // LDR R15,=...

    char* t_data = (char*) allocate_trampoline(16);
    memcpy(t_data, data, 8);
    memcpy(&t_data[8], pc_ldr_instr, 4);
    *((void**) &t_data[12]) = data + 8;
    *orig = t_data;

    int ps = sysconf(_SC_PAGESIZE);
    void* data_page = (void*) ((size_t) ptr / ps * ps);
    if (mprotect(data_page, (size_t) data - (size_t) data_page + 8, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "mprotect failed");
    memcpy(data, pc_ldr_instr, 4);
    *((void**) &data[4]) = hook;

    __builtin___clear_cache((char*) data, (char*) data + 8);
}

void mem_so_patcher::hook_linker_syscall(void* linker_start, size_t linker_size,
                                         const char* name, void* pattern, size_t pattern_size,
                                         void* hook, void** orig) {
    void* addr = memmem(linker_start, linker_size, pattern, pattern_size);
    if (addr != nullptr) {
        __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Hooking %s at %x", name, (size_t) addr);
        hook_syscall(addr, hook, orig);
    } else {
        __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Did not find %s", name);
    }
}

void mem_so_patcher::hook_linker_syscalls() {
    if (linker_hooked)
        return;
    linker_hooked = true;

    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Patching linker");
    void* linker_map_start = nullptr;
    size_t linker_map_size = 0;
    maps_helper helper;
    maps_helper::map* map;
    while ((map = helper.next()) != nullptr) {
        if (strcmp(map->name, "/system/bin/linker") == 0 && map->x) {
            linker_map_start = (void*) map->start;
            linker_map_size = map->end - map->start;
            break;
        }
    }
    if (!linker_map_start) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to find the linker map");
        return;
    }
#define HOOK_SYSCALL(name, hook) \
    hook_linker_syscall(linker_map_start, linker_map_size, #name, name, sizeof(name), (void*) hook##_hook, (void**) &hook##_orig);

    HOOK_SYSCALL(pattern_syscall_05_open, linker_hooks::open)
    HOOK_SYSCALL(pattern_syscall_142_openat, linker_hooks::openat)
    HOOK_SYSCALL(pattern_syscall_C0_mmap2, linker_hooks::mmap2)

#undef HOOK_SYSCALL
}

int (*mem_so_patcher::linker_hooks::open_orig)(const char *, int, unsigned short);
int mem_so_patcher::linker_hooks::open_hook(const char *filename, int flags, unsigned short mode) {
    int ret = open_orig(filename, flags, mode);
    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "open(%s) = %i", filename, ret);

    if (ret >= 0) {
        auto it = libs.find(filename);
        if (it != libs.end()) {
            it->second.fd = ret;
        }
    }
    return ret;
}

int (*mem_so_patcher::linker_hooks::openat_orig)(int, const char*, int, int);
int mem_so_patcher::linker_hooks::openat_hook(int dirfd, const char *filename, int flags,
                                              int mode) {
    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "openat(%i %s) = %i", dirfd, filename, 0);
    int ret = openat_orig(dirfd, filename, flags, mode);
    if (dirfd == AT_FDCWD && ret >= 0) {
        auto it = libs.find(filename);
        if (it != libs.end()) {
            it->second.fd = ret;
        }
    }
    return ret;
}

void* (*mem_so_patcher::linker_hooks::mmap2_orig)(void *, size_t, int, int, int, size_t);
void* mem_so_patcher::linker_hooks::mmap2_hook(void *addr, size_t len, int prot, int flags,
                                               int fd, size_t pgoff) {
    lib_info const* info = nullptr;
    bool has_matching_patch = false;
    size_t offset = pgoff * 4096;
    if (!(flags & MAP_ANONYMOUS)) {
        for (auto const& p : libs) {
            if (p.second.fd == fd) {
                info = &p.second;
                break;
            }
        }
        if (info != nullptr) {
            for (auto const& p : info->patches) {
                size_t pend = p.start + p.data.size();
                if (pend > offset && p.start < offset + len) {
                    has_matching_patch = true;
                    break;
                }
            }
        }
    }
    if (has_matching_patch)
        prot |= PROT_WRITE;
    void* ret = mmap2_orig(addr, len, prot, flags, fd, pgoff);

    if (has_matching_patch && ret != nullptr) {
        __android_log_print(ANDROID_LOG_VERBOSE, TAG, "mmap2() =%x", (size_t) ret);
        for (auto const& p : info->patches) {
            size_t pend = p.start + p.data.size();
            if (pend > offset && p.start < offset + len) {
                ssize_t poff = (ssize_t) p.start - offset;
                size_t ploff = 0;
                if (poff < 0) {
                    ploff = (size_t) (-poff);
                    poff = 0;
                }
                memcpy(((char*) ret) + poff, p.data.data() + ploff,
                       std::min(p.data.size() - ploff, len - poff));
            }
        }
    }

    return ret;
}

void* mem_so_patcher::load_library(std::string const& path, std::vector<patch> patches) {
    hook_linker_syscalls();
    libs[path].patches = patches;
    void* ret = dlopen(path.c_str(), RTLD_LAZY);
    libs.erase(path);
    return ret;
}