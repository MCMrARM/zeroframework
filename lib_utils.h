#pragma once

#include <elf.h>

class lib_utils {

public:
    static void* find_lib_base(void* handle, const char* lookup_symbol = "__bss_start");

    static Elf32_Phdr* find_dynamic(void* base);

};