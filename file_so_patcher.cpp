#include "file_so_patcher.h"

#include <sys/mman.h>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

using namespace zerof;

std::string file_so_patcher::get_lib_filename(std::string const &path) {
    auto iof = path.rfind('/');
    if (iof != std::string::npos)
        return path.substr(iof + 1);
    return path;
}

void* file_so_patcher::load_library(std::string const &path, std::vector<so_patch> patches) {
    int ofd = open(path.c_str(), O_RDONLY);
    if (ofd < 0)
        throw std::runtime_error("open() of the original lib failed");

    off_t size = lseek(ofd, 0, SEEK_END);
    off_t seek_back = lseek(ofd, 0, SEEK_SET);
    if (size == (off_t) -1 || seek_back == (off_t) -1)
        throw std::runtime_error("lseek() failed");

    std::string tmp_path = tmp_dir + "/" + get_lib_filename(path);
    int nfd = open(tmp_path.c_str(), O_RDWR | O_CREAT, 0600);
    if (nfd < 0) {
        close(ofd);
        throw std::runtime_error("open() of the new lib failed");
    }
    if (ftruncate(nfd, size) < 0) {
        close(ofd);
        close(nfd);
        throw std::runtime_error("ftruncate() failed");
    }

    void* ptr = mmap(nullptr, (size_t) size, PROT_READ | PROT_WRITE, MAP_SHARED, nfd, 0);
    if (ptr == nullptr) {
        close(ofd);
        close(nfd);
        throw std::runtime_error("mmap() failed");
    }
    char* current = (char*) ptr;
    char* end = current + size;
    ssize_t r;
    while (current < end && (r = read(ofd, current, (size_t) (end - current))) > 0) {
        current += r;
    }
    if (current != end)
        throw std::runtime_error("reading failed");
    for (auto const& p : patches)
        memcpy(&((char*) ptr)[p.start], p.data.data(), p.data.size());
    void* lib_handle = dlopen(tmp_path.c_str(), RTLD_LAZY);
    munmap(ptr, (size_t) size);
    return lib_handle;
}