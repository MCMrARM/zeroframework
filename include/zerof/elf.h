#include <elf.h>

namespace zerof {

namespace elf {
#ifdef __LP64__
    using Word = Elf64_Word;
    using Addr = Elf64_Addr;
    using Rel = Elf64_Rel;
    using Rela = Elf64_Rela;
    using Sym = Elf64_Sym;
    using Dyn = Elf64_Dyn;
    using Ehdr = Elf64_Ehdr;
    using Phdr = Elf64_Phdr;
#else
    using Word = Elf32_Word;
    using Addr = Elf32_Addr;
    using Rel = Elf32_Rel;
    using Rela = Elf32_Rela;
    using Sym = Elf32_Sym;
    using Dyn = Elf32_Dyn;
    using Ehdr = Elf32_Ehdr;
    using Phdr = Elf32_Phdr;
#endif
}

}