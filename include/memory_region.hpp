#pragma once

#include "core/types.h"
#include "symbol.hpp"

#include <string>

struct MemoryRegion {
    usize start, end;
    char perms[5];
    std::string name;
};

void load_memory_regions(pid_t pid);
void handle_maps(pid_t pid, char *args);
bool address_is_valid(pid_t pid, usize addr);
usize get_symbol_address(const Symbol &sym, std::string &program_name, bool &found);
