#include <zerof/maps_helper.h>

#include <vector>
#include <stdexcept>

using namespace zerof;

int maps_helper::_getline(char** lineptr, size_t* n, FILE* stream) {
    if (*lineptr == nullptr || *n < 16) {
        *n = 64;
        *lineptr = (char*) (*lineptr == nullptr ? malloc(*n) : realloc(*lineptr, *n));
        if (*lineptr == nullptr)
            return -1;
    }
    int c, pos = 0;
    while ((c = getc(stream)) != EOF) {
        (*lineptr)[pos++] = (char) c;
        if (pos >= *n) {
            *n *= 2;
            *lineptr = (char*) realloc(*lineptr, *n);
            if (*lineptr == nullptr)
                return -1;
        }
        if (c == '\n')
            break;
    }
    (*lineptr)[pos] = 0;
    return pos;
}

maps_helper::maps_helper() {
    file = fopen("/proc/self/maps", "r");
    if (file == nullptr)
        throw std::runtime_error("Failed to open /proc/self/maps");
}
maps_helper::~maps_helper() {
    if (file != nullptr)
        fclose(file);
}

maps_helper::map* maps_helper::next() {
    if (file == nullptr || feof(file))
        return nullptr;
    char r, w, x;
    if (fscanf(file, (sizeof(void*) == 8 ? "%16lx-%16lx %c%c%c%c %Lx %x:%x %Lu"
                                         : "%08lx-%08lx %c%c%c%c %Lx %x:%x %Lu"),
               &current.start, &current.end, &r, &w, &x, &current.shared,
               &current.file_offset, &current.dev_major, &current.dev_minor, &current.inode) < 9)
        return nullptr;
    if (_getline(&name_buf, &name_buf_size, file) <= 0)
        return nullptr;
    current.r = (r == 'r');
    current.w = (w == 'w');
    current.x = (x == 'x');
    {
        size_t name_start;
        for (name_start = 0; name_start < name_buf_size; name_start++) {
            if (name_buf[name_start] != ' ')
                break;
        }
        char* name = &name_buf[name_start];
        ssize_t name_len;
        for (name_len = (ssize_t) strlen(name) - 1; name_len >= 0; name_len--) {
            if (name[name_len] != ' ' && name[name_len] != '\n') {
                name[name_len + 1] = '\0';
                break;
            }
        }
        current.name = name;
    }
    return &current;
}
