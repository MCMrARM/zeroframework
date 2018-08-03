#include "soname_patch_creator.h"

#include <elf.h>
#include <android/log.h>

#define TAG "SoPatcher"

std::vector<so_patch> soname_patch_creator::create_patch_list(
        FILE *file, const char* soname) {
    std::vector<so_patch> patches;

    Elf32_Ehdr header;
    if (fseek(file, 0, SEEK_SET) != 0 ||
            fread(&header, sizeof(Elf32_Ehdr), 1, file) != 1)
        throw soname_patch_error("Failed to read the ELF header");
    char phdr[header.e_phentsize * header.e_phnum];
    if (fseek(file, (long) header.e_phoff, SEEK_SET) != 0 ||
            fread(&phdr, header.e_phentsize, header.e_phnum, file) != header.e_phnum)
        throw soname_patch_error("Failed to read the program headers");
    Elf32_Phdr *dynamic = nullptr;
    for (int i = 0; i < header.e_phnum; i++) {
        Elf32_Phdr &entry = *((Elf32_Phdr *) &phdr[header.e_phentsize * i]);
        if (entry.p_type == PT_DYNAMIC) {
            dynamic = &entry;
            break;
        }
    }
    if (dynamic == nullptr)
        throw soname_patch_error("Could not find the PT_DYNAMIC header");

    size_t dyn_data_count = (size_t) (dynamic->p_filesz / sizeof(Elf32_Dyn));
    Elf32_Dyn dyn_data[dyn_data_count];
    if (fseek(file, (long) dynamic->p_offset, SEEK_SET) != 0 ||
            fread(dyn_data, sizeof(Elf32_Dyn), dyn_data_count, file) != dyn_data_count)
        throw soname_patch_error("Failed to read PT_DYNAMIC data");

    /* make sure SONAME isn't already there */
    Elf32_Word strtab_off = 0, strtab_size = 0;
    for (int j = 0; j < dyn_data_count; j++) {
        if (dyn_data[j].d_tag == DT_SONAME) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "SONAME already exists, skipping patching");
            return {};
        } else if (dyn_data[j].d_tag == DT_STRTAB) {
            strtab_off = dyn_data[j].d_un.d_ptr;
        } else if (dyn_data[j].d_tag == DT_STRSZ) {
            strtab_size = dyn_data[j].d_un.d_ptr;
        }
    }
    /* dump string table */
    char *strtab_data = new char[strtab_size];
    assert(fseek(file, (long) strtab_off, SEEK_SET) == 0);
    assert(fread(strtab_data, strtab_size, 1, file) == 1);

    /* add libminecraftpe.so to string table */
    const char *to_replace = "_ZNK19AppLifecycleContext17getHasWindowFocusEv";
    size_t to_replace_len = strlen(to_replace) + 1;
    size_t replace_str_off = 0;
    while (replace_str_off < strtab_size) {
        size_t start = replace_str_off;
        while (replace_str_off < strtab_size) {
            if (strtab_data[replace_str_off++] == '\0') {
                break;
            }
        }
        if (replace_str_off - start == to_replace_len &&
                memcmp(&strtab_data[start], to_replace, to_replace_len) == 0) {
            replace_str_off = start;
            break;
        }
    }
    if (replace_str_off >= strtab_size)
        throw soname_patch_error("Failed to find a string to replace");
    patches.push_back({strtab_off + replace_str_off,
                       std::vector<char>(soname, soname + strlen(soname) + 1)});
    delete[] strtab_data;
    /* add the tag */
    bool found_null_tag = false;
    for (int i = 0; i < dyn_data_count; i++) {
        if (dyn_data[i].d_tag == DT_NULL) {
            found_null_tag = true;
            dyn_data[i].d_tag = DT_SONAME;
            dyn_data[i].d_un.d_ptr = (Elf32_Addr) replace_str_off;
            patches.push_back({dynamic->p_offset + i * sizeof(Elf32_Dyn),
                               std::vector<char>((char*) &dyn_data[i], (char*) &dyn_data[i + 1])});
            break;
        }
    }
    if (!found_null_tag)
        throw soname_patch_error("Failed to find a PT_DYNAMIC tag to replace");
    return patches;
}