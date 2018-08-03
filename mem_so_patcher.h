#pragma once

#include <string>
#include <vector>
#include <map>
#include "so_patch.h"

/**
 * code_region represents a memory region which is supposed to be mapped as exec+write, in which
 * we place trampoline functions.
 */
class code_region {

public:
    void* start;
    void* end;
    void* current;

public:
    code_region() : start(nullptr), end(nullptr), current(nullptr) {}
    code_region(void* start, size_t size) : start(start), end((void*) ((size_t) start + size)),
                                            current(start) {}
    code_region(code_region&& r) : start(r.start), end(r.end), current(r.current) {
        r.release();
    }

    ~code_region() {
        free();
    }

    operator bool() {
        return start != nullptr;
    }

    void free();

    void release() {
        start = end = current = nullptr;
    }

    code_region const& operator=(code_region&& r) {
        start = r.start;
        end = r.end;
        current = r.current;
        r.release();
        return *this;
    }


    /**
     * Take the specified size bytes from this page for a trampoline.
     */
    void* take(size_t size);

    /**
     * This is the primary function to allocate a code_region, with the specified min_size, which
     * will be rounded up to the nearest page size.
     */
    static code_region alloc(size_t min_size);

};

class mem_so_patcher {

public:
    struct lib_info {
        int fd = -1;
        std::vector<so_patch> patches;
    };


    static bool linker_hooked;
    static std::map<std::string, lib_info> libs;
    static std::vector<code_region> code_regions;

    static void* allocate_trampoline(size_t size);

    static void hook_syscall(void* ptr, void* hook, void** orig);

    static bool hook_linker_syscall(void* linker_start, size_t linker_size,
                                    const char* name, void* pattern, size_t pattern_size,
                                    void* hook, void** orig);

    static unsigned int* simple_find(unsigned int* haystack, size_t haystack_size,
                                     unsigned int* needle, size_t needle_size, unsigned int* mask);

    static void hook_linker_syscalls();


    struct linker_hooks {
        static int (*open_orig)(const char*, int, unsigned short);
        static int open_hook(const char* filename, int flags, unsigned short mode);

        static int (*openat_orig)(int, const char*, int, int);
        static int openat_hook(int dirfd, const char* filename, int flags, int mode);

        static void* (*mmap2_orig)(void*, size_t, int, int, int, size_t);
        static void* mmap2_hook(void* addr, size_t len, int prot, int flags, int fd, size_t pgoff);
    };

public:
    static void* load_library(std::string const& path, std::vector<so_patch> patches);

};