#include "memory_region.hpp"

#include "core/logger.h"
#include "symbol.hpp"

#include <cstring>
#include <vector>

static std::vector<MemoryRegion> regions;

void load_memory_regions(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        error("Could not open memory maps");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        MemoryRegion region;
        char path[256] = {0};

        // Parse line
        if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %s", &region.start, &region.end, region.perms, path) >= 3) {
            region.name = std::string(path);
            regions.push_back(region);
        }
    }

    fclose(maps);
}

static void print_memory_regions() {
    printf("Memory maps:\n");
    for (const MemoryRegion &region : regions) {
        printf("%016lx-%016lx %s %s\n", region.start, region.end, region.perms, region.name.c_str());
    }
}

void handle_maps(pid_t pid, char *args) {
    print_memory_regions();
}

bool address_is_valid(pid_t pid, usize addr) {
    for (const auto &region : regions) {
        if (addr >= region.start && addr < region.end && strchr(region.perms, 'r')) {
            return true;
        }
    }

    return false;
}

// usize get_symbol_address(const char *name, bool *found) {
//     // Try to parse as hex address first
//     usize addr;
//     if (sscanf(name, "%lx", &addr) == 1) {
//         if (found) *found = true;
//         return addr;
//     }

//     // Search symbols
//     for (const auto &sym : symbols) {
//         if (sym.name == name) {
//             // Get the base address from memory maps
//             for (const auto &region : regions) {
//                 if (region.perms[2] == 'x' && region.name.find("test") != std::string::npos) {
//                     if (found) *found = true;
//                     return region.start + sym.address;
//                 }
//             }
//         }
//     }

//     if (found) *found = false;
//     return 0;
// }

// usize get_symbol_address(const Symbol &sym, std::string &program_name, bool &found) {
//     for (const auto &region : regions) {
//         if (region.perms[2] == 'x' && region.name.find(program_name) != std::string::npos) {
//             found = true;
//             return region.start + sym.address;
//         }
//     }

//     return 0;
// }

// usize get_symbol_address(const Symbol &sym, std::string &program_name, bool &found) {
//     printf("Debug: Looking for program '%s' in regions:\n", program_name.c_str());
//     for (const auto &region : regions) {
//         printf("  %016lx-%016lx %s '%s'\n", region.start, region.end, region.perms, region.name.c_str());
//         if (region.perms[2] == 'x' && region.name.find(program_name) != std::string::npos) {
//             found = true;
//             return region.start + sym.address;
//         }
//     }
//     found = false;
//     return 0;
// }

usize get_symbol_address(const Symbol &sym, std::string &program_name, bool &found) {
    printf("Debug: Looking for program '%s' in regions:\n", program_name.c_str());
    for (const auto &region : regions) {
        printf("  %016lx-%016lx %s '%s'\n", region.start, region.end, region.perms, region.name.c_str());
        if (region.perms[2] == 'x' && region.name.find(program_name) != std::string::npos) {
            found = true;
            // The symbol address from the ELF file is an offset from base + 0x400000
            usize adjusted_addr = sym.address - 0x400000;
            return region.start + adjusted_addr;
        }
    }
    found = false;
    return 0;
}
