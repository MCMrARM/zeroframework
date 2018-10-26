#pragma once

#include <vector>

namespace zerof {

struct so_patch {
    size_t start;
    std::vector<char> data;
};

}