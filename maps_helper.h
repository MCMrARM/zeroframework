#pragma once

#include <string>

namespace zerof {

class maps_helper {

private:
    static int _getline(char** lineptr, size_t* n, FILE* stream);

public:
    struct map {
        long unsigned int start, end;
        long long unsigned int file_offset;
        long long inode;
        bool r, w, x;
        char shared;
        int dev_major, dev_minor;
        const char* name;
    };

private:
    FILE* file;
    char* name_buf = nullptr;
    size_t name_buf_size = 0;
    map current;

public:
    maps_helper();
    ~maps_helper();

    map* next();

};

}