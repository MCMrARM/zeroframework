#pragma once

#include <string>
#include <vector>
#include "so_patch.h"

namespace zerof {

class ptrace_mem_so_patcher {

public:

private:
    struct patch_context {
        pid_t pid;
        std::string patch_lib_name;
        std::vector<so_patch> patches;
        std::atomic_bool finished;
    };

    static bool wait_for_syscall(patch_context* parg, pid_t pid);

    static int handle_ptrace(void* arg);

public:
    static void* load_library(std::string path, std::vector<so_patch> patches);

};

}