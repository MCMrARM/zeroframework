#pragma once

#include <string>
#include <vector>
#include <map>
#include "so_patch.h"

namespace zerof {

class file_so_patcher {

private:
    std::string tmp_dir;

    static std::string get_lib_filename(std::string const& path);

public:
    file_so_patcher(std::string const& tmp_dir) : tmp_dir(tmp_dir) {}

    void* load_library(std::string const& path, std::vector<so_patch> patches);

};

}