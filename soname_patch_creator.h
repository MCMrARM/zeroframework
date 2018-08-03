#pragma once

#include <vector>
#include <exception>
#include <string>
#include "so_patch.h"

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
    static std::vector<so_patch> create_patch_list(FILE *file, const char* soname);

};