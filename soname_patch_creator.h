#pragma once

#include <vector>
#include <exception>
#include <string>
#include "mem_so_patcher.h"

class soname_patch_error : public std::exception {
private:
    std::string message;

public:
    soname_patch_error(std::string message) : message(std::move(message)) {}
    ~soname_patch_error() override {}

    const char *what() const noexcept override { return message.c_str(); }
};

class soname_patch_creator {

public:
    static std::vector<mem_so_patcher::patch> create_patch_list(FILE *file, const char* soname);

};