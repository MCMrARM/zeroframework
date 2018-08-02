#pragma once

#include <vector>

struct so_patch {
    size_t start;
    std::vector<char> data;
};