#pragma once

#include "core/types.h"

#include <string>

struct Symbol {
    std::string name;
    usize address;
    usize size;
    u8 type;
    u8 binding;
};

void load_symbols(const std::string program_path);
void handle_symbols(pid_t pid, char *args);
usize get_symbol_address(std::string program_path, const char *name, bool &found);
