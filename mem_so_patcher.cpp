#include "mem_so_patcher.h"
#include "maps_helper.h"

#include <sys/mman.h>
#include <sys/sysconf.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <chrono>

#define TAG "MemSoPatcher"

bool mem_so_patcher::linker_hook_attempted = false;
bool mem_so_patcher::linker_hook_successful = false;
std::map<std::string, mem_so_patcher::lib_info> mem_so_patcher::libs;
std::vector<code_region> mem_so_patcher::code_regions;

#ifdef __i386__
static unsigned char pattern_syscall_05_open[]    = { 0x53, 0x51, 0x52, 0x56, 0x8B, 0x5C, 0x24, 0x14, 0x8B, 0x4C, 0x24, 0x18, 0x8B, 0x54, 0x24, 0x1C, 0x8B, 0x74, 0x24, 0x20, 0xB8, 0x05, 0x00, 0x00, 0x00, 0xCD, 0x80 };
static unsigned char pattern_syscall_142_openat[] = { 0x53, 0x51, 0x52, 0x56, 0x8B, 0x5C, 0x24, 0x14, 0x8B, 0x4C, 0x24, 0x18, 0x8B, 0x54, 0x24, 0x1C, 0x8B, 0x74, 0x24, 0x20, 0xB8, 0x27, 0x01, 0x00, 0x00, 0xCD, 0x80 };
static unsigned char pattern_syscall_C0_mmap2[]   = { 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x8B, 0x5C, 0x24, 0x1C, 0x8B, 0x4C, 0x24, 0x20, 0x8B, 0x54, 0x24, 0x24, 0x8B, 0x74, 0x24, 0x28, 0x8B, 0x7C, 0x24, 0x2C, 0x8B, 0x6C, 0x24, 0x30, 0xB8, 0xC0, 0x00, 0x00, 0x00, 0xCD, 0x80 };
#else
static unsigned char pattern_syscall_05_open[]    = { 0x07, 0xC0, 0xA0, 0xE1, 0x05, 0x70, 0xA0, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0x0C, 0x70, 0xA0, 0xE1 };
static unsigned char pattern_syscall_142_openat[] = { 0x07, 0xC0, 0xA0, 0xE1, 0x42, 0x71, 0x00, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0x0C, 0x70, 0xA0, 0xE1 };
static unsigned char pattern_syscall_C0_mmap2[]   = { 0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0x00, 0x2D, 0xE9, 0x70, 0x00, 0x9C, 0xE8, 0xC0, 0x70, 0xA0, 0xE3, 0x00, 0x00, 0x00, 0xEF, 0xF0, 0x00, 0xBD, 0xE8 };

static unsigned int pattern_syscall_alt_short[]        = { 0xE1A0C007, 0xE59F7014, 0xEF000000, 0xE1A0700C };
static unsigned int pattern_syscall_alt_short_masks[]  = { 0xFFFFFFFF, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF };

static unsigned int pattern_syscall_alt_long[]         = { 0xE1A0C00D, 0xE92D00F0, 0xE89C0070, 0xE59F7014, 0xEF000000, 0xE8BD00F0 };
static unsigned int pattern_syscall_alt_long_masks[]   = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF };
#endif

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
    unsigned char* data = (unsigned char*) ptr;
#ifdef __i386__
    size_t trampoline_bytes = 0;
    for ( ; trampoline_bytes < 5; ) {
        unsigned char b = data[trampoline_bytes];
        if (b >= 0x50 && b <= 0x50 + 8) // PUSH
            trampoline_bytes++;
        else if (b == 0x8B) // MOV r16, r/m16
            trampoline_bytes += 4;
        else
            abort();
    }

    char* t_data = (char*) allocate_trampoline(trampoline_bytes + 5);
    memcpy(t_data, data, trampoline_bytes);
    t_data[trampoline_bytes] = 0xe9;
    *((int*) &t_data[trampoline_bytes + 1]) = (int) (data + trampoline_bytes) - (int) (t_data + trampoline_bytes) - 5;
    *orig = t_data;

    int ps = sysconf(_SC_PAGESIZE);
    void* data_page = (void*) ((size_t) ptr / ps * ps);
    if (mprotect(data_page, (size_t) data - (size_t) data_page + 5, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "mprotect failed");
    data[0] = 0xe9;
    *((int*) &data[1]) = (int) (size_t) hook - (int) (size_t) data - 5;

    __builtin___clear_cache((char*) data, (char*) data + 5);
#else
    bool thumb = (((size_t) ptr) & 1) != 0;
    if (thumb) { // thumb is not currently used
        abort();
    }

    unsigned char pc_ldr_instr[] = {0x04, 0xF0, 0x1F, 0xE5}; // LDR R15,=...

    bool has_ldr = (((unsigned int*) data)[1] & 0xFFFFFF00) == 0xE59F7000;
    char* t_data = (char*) allocate_trampoline(has_ldr ? 20 : 16);
    memcpy(t_data, data, 8);
    memcpy(&t_data[8], pc_ldr_instr, 4);
    *((void**) &t_data[12]) = data + 8;
    if (has_ldr) {
        ((unsigned int*) t_data)[1] = 0xE59F7004;
        unsigned int* oinstr = ((unsigned int*) data + 1);
        ((unsigned int*) t_data)[16 / 4] = *(unsigned int*)
                ((unsigned char*) oinstr + ((*oinstr & 0xFF) + 8));
    }
    *orig = t_data;

    int ps = sysconf(_SC_PAGESIZE);
    void* data_page = (void*) ((size_t) ptr / ps * ps);
    if (mprotect(data_page, (size_t) data - (size_t) data_page + 8,
                 PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "mprotect failed");
    memcpy(data, pc_ldr_instr, 4);
    *((void**) &data[4]) = hook;

    __builtin___clear_cache((char*) data, (char*) data + 8);
#endif
}

bool mem_so_patcher::hook_linker_syscall(void* linker_start, size_t linker_size,
                                         const char* name, void* pattern, size_t pattern_size,
                                         void* hook, void** orig) {
    void* addr = simple_find((unsigned int*) linker_start, linker_size,
                             (unsigned int*) pattern, pattern_size, nullptr);
    if (addr != nullptr) {
        __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Hooking %s at %x", name, (size_t) addr);
        hook_syscall(addr, hook, orig);
        return true;
    } else {
        __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Did not find %s", name);
        return false;
    }
}

unsigned int* mem_so_patcher::simple_find(unsigned int *haystack, size_t haystack_size,
                                          unsigned int *needle, size_t needle_size,
                                          unsigned int *mask) {
    void* haystack_end = (void*) ((size_t) haystack + haystack_size);
    size_t match_i = 0;
    for (unsigned int* p = haystack; p < haystack_end; p++) {
        unsigned int m = mask != nullptr ? mask[match_i] : 0xFFFFFFFF;
        if (((*p) & m) == (needle[match_i] & m)) {
            ++match_i;
            if (match_i == needle_size / sizeof(unsigned int))
                return p - match_i + 1;
        } else if (match_i != 0) {
            match_i = 0;
            --p; // reiterate this one
        }
    }
    return nullptr;
}

bool mem_so_patcher::hook_linker_syscalls() {
    if (linker_hook_attempted)
        return linker_hook_successful;
    linker_hook_attempted = true;

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
        return false;
    }
#define HOOK_SYSCALL(name, hook) \
    hook_linker_syscall(linker_map_start, linker_map_size, #name, name, sizeof(name), \
        (void*) hook##_hook, (void**) &hook##_orig)

    auto start = std::chrono::steady_clock::now();
    bool hooked_open_or_openat = false;
    bool hooked_mmap2 = HOOK_SYSCALL(pattern_syscall_C0_mmap2, linker_hooks::mmap2);
    if (hooked_mmap2) {
        bool hooked_open = HOOK_SYSCALL(pattern_syscall_05_open, linker_hooks::open);
        bool hooked_openat = HOOK_SYSCALL(pattern_syscall_142_openat, linker_hooks::openat);
        hooked_open_or_openat = hooked_open || hooked_open_or_openat;
    } else {
#ifndef __i386__
        // something is wrong clearly - try to find the alternative pattern
        unsigned int* p = (unsigned int*) linker_map_start;
        size_t linker_map_end = (size_t) linker_map_start + linker_map_size;
        while ((p = simple_find(p, linker_map_end - (size_t) p,
                                pattern_syscall_alt_short, sizeof(pattern_syscall_alt_short_masks),
                                pattern_syscall_alt_short_masks)) != nullptr) {
            //__android_log_print(ANDROID_LOG_ERROR, TAG, "Found match at %x", (size_t) p - (size_t) linker_map_start);
            // handle the match
            unsigned int off = *(unsigned int*)
                    ((unsigned char*) (p + 1) + ((*(p + 1)) & 0xFF) + 8);
            //__android_log_print(ANDROID_LOG_ERROR, TAG, "Found match at %x = %x %x", (size_t) p, ((*(p + 1)) & 0xFF), off);

            if (off == 0x05) {
                hook_syscall(p, (void *) linker_hooks::open_hook, (void **) &linker_hooks::open_orig);
                hooked_open_or_openat = true;
            }
            if (off == 0x142) {
                hook_syscall(p, (void *) linker_hooks::openat_hook, (void **) &linker_hooks::openat_orig);
                hooked_open_or_openat = true;
            }

            p += sizeof(pattern_syscall_alt_short_masks) / sizeof(int);
        }
        p = (unsigned int*) linker_map_start;
        while ((p = simple_find(p, linker_map_end - (size_t) p,
                                pattern_syscall_alt_long, sizeof(pattern_syscall_alt_long_masks),
                                pattern_syscall_alt_long_masks)) != nullptr) {
            //__android_log_print(ANDROID_LOG_ERROR, TAG, "Found long match at %x", (size_t) p);
            // handle the match
            unsigned int off = *(unsigned int*)
                    ((unsigned char*) (p + 3) + ((*(p + 3)) & 0xFF) + 8);
            //__android_log_print(ANDROID_LOG_ERROR, TAG, "Found long  match at %x = %x", (size_t) p, off);

            if (off == 0xC0) {
                hook_syscall(p, (void *) linker_hooks::mmap2_hook, (void **) &linker_hooks::mmap2_orig);
                hooked_mmap2 = true;
            }

            p += sizeof(pattern_syscall_alt_short_masks) / sizeof(int);
        }
#endif
    }
    auto end = std::chrono::steady_clock::now();
    __android_log_print(ANDROID_LOG_ERROR, TAG, "Took %f seconds", std::chrono::duration_cast<
            std::chrono::duration<float>>(end - start).count());
#undef HOOK_SYSCALL

    linker_hook_successful = hooked_open_or_openat && hooked_mmap2;
    return linker_hook_successful;
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
    int ret = openat_orig(dirfd, filename, flags, mode);
    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "openat(%i %s) = %i", dirfd, filename, ret);
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

void* mem_so_patcher::load_library(std::string const& path, std::vector<so_patch> patches) {
    if (!hook_linker_syscalls())
        return nullptr;
    libs[path].patches = patches;
    void* ret = dlopen(path.c_str(), RTLD_LAZY);
    libs.erase(path);
    return ret;
}