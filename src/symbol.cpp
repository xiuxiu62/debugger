#include "symbol.hpp"

#include "core/logger.h"
#include "memory_region.hpp"

#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#define PATH_MAX 256

static std::vector<Symbol> symbols;

void load_symbols(const std::string program_path) {
    printf("Attempting to load symbols from: %s\n", program_path.c_str());
    printf("Current working directory: %s\n", getcwd(nullptr, 0));

    // Try direct open first
    i32 fd = open(program_path.c_str(), O_RDONLY);
    if (fd < 0) {
        printf("Direct open failed: %s\n", strerror(errno));

        // Try with realpath
        char resolved_path[PATH_MAX];
        if (realpath(program_path.c_str(), resolved_path) == nullptr) {
            printf("realpath failed: %s\n", strerror(errno));
            return;
        }

        printf("Resolved path: %s\n", resolved_path);
        fd = open(resolved_path, O_RDONLY);
        if (fd < 0) {
            printf("Open after realpath failed: %s\n", strerror(errno));
            return;
        }
    }

    //     // Rest of the function...

    // void load_symbols(const std::string program_path) {
    //     char resolved_path[PATH_MAX];
    //     if (realpath(program_path.c_str(), resolved_path) == nullptr) {
    //         error("realpath %s", program_path.c_str());
    //         return;
    //     }

    //     printf("Loading symbols from: %s\n", resolved_path);

    //     i32 fd = open(resolved_path, O_RDONLY);
    //     if (fd < 0) {
    //         error("open %s: %s", resolved_path, strerror(errno));
    //         return;
    //     }

    //     // Rest of the function...
    // }

    // void load_symbols(const std::string program_path) {
    //     i32 fd = open(program_path.c_str(), O_RDONLY);
    //     if (fd < 0) {
    //         error("open %s", program_path.c_str());
    //         return;
    //     }

    // Get file size
    i64 size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map the entire file
    void *data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        error("mmap");
        close(fd);
        return;
    }

    Elf64_Ehdr *ehdr = static_cast<Elf64_Ehdr *>(data);
    Elf64_Shdr *section_headers;
    Elf64_Shdr *symtab = nullptr;
    Elf64_Shdr *strtab = nullptr;
    char *section_names;

    Elf64_Sym *syms;
    char *strtable;
    int symbol_count;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        error("Not a valid ELF file\n");
        goto cleanup;
    }

    section_headers = reinterpret_cast<Elf64_Shdr *>(static_cast<char *>(data) + ehdr->e_shoff);
    section_names = static_cast<char *>(data) + section_headers[ehdr->e_shstrndx].sh_offset;

    for (usize i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *header = &section_headers[i];
        char *section_name = section_names + header->sh_name;

        if (strcmp(section_name, ".symtab") == 0) {
            symtab = header;
        } else if (strcmp(section_name, ".strtab") == 0) {
            strtab = header;
        }
    }

    if (!symtab || !strtab) {
        error("No symbol table found\n");
        goto cleanup;
    }

    syms = reinterpret_cast<Elf64_Sym *>(static_cast<char *>(data) + symtab->sh_offset);
    strtable = static_cast<char *>(data) + strtab->sh_offset;
    symbol_count = symtab->sh_size / sizeof(Elf64_Sym);

    symbols.clear();
    for (usize i = 0; i < symbol_count; i++) {
        if (syms[i].st_name == 0) continue; // Skip unnamed symbols

        // Only include function symbols
        if (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC) {
            Symbol sym;
            sym.name = strtable + syms[i].st_name;
            sym.address = syms[i].st_value;
            sym.size = syms[i].st_size;
            sym.type = ELF64_ST_TYPE(syms[i].st_info);
            sym.binding = ELF64_ST_BIND(syms[i].st_info);
            symbols.push_back(sym);
        }
    }

cleanup:
    munmap(data, size);
    close(fd);
}

void handle_symbols(pid_t pid, char *args) {
    printf("Program symbols:\n");
    for (const Symbol &symbol : symbols) {
        printf("%016lx %zu %s\n", symbol.address, symbol.size, symbol.name.c_str());
    }
}

usize get_symbol_address(const Symbol &sym, std::string &program_name, bool &found);

usize get_symbol_address(std::string program_path, const char *name, bool &found) {
    // Search symbols
    for (const auto &sym : symbols) {
        if (sym.name == name) {
            // Extract just the program name from the full path
            usize slash_pos = program_path.find_last_of('/');
            std::string program_name =
                (slash_pos == std::string::npos) ? program_path : program_path.substr(slash_pos + 1);

            // Get the base address from memory maps
            usize maybe_addr = get_symbol_address(sym, program_name, found);
            if (found) {
                return maybe_addr;
            }
        }
    }

    return 0;
}
