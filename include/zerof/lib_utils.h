#pragma once

#include "elf.h"
#include <vector>

namespace zerof {

class lib_utils {

public:
    static void* find_lib_base(void* handle, const char* lookup_symbol = "__bss_start");

    static elf::Phdr* find_dynamic(void* base);

    static std::vector<elf::Dyn> read_original_dynamic(void* base);
};

}