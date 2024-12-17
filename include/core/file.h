#pragma once

#include "core/logger.h"
#include "core/types.h"

#include <cstdio>
#include <cstdlib>

static inline void close_file(FILE *file);

static FILE *open_file(const char *path, const char *modes) {
    FILE *file;
#ifdef _WIN32
    errno_t err = fopen_s(&file, path, modes);
    if (err) {
        if (file) close_file(file);
        file = nullptr;
    }
#else
    file = fopen(path, modes);
#endif /* ifdef WIN32 */
    return file;
}

static inline void close_file(FILE *file) {
    fclose(file);
}

// TODO: return boolean instead, taking a data pointer to assign to the resulting data
// Reads contents of a file into the data buffer, returning the length of the file
// A return of -1 means the
// This allocates the buffer and must be cleaned up
static isize read_file(const char *path, char **data) {
#define finish()                                                                                                       \
    close_file(file);                                                                                                  \
    return -1;

    FILE *file = open_file(path, "rb");
    if (!file) {
        info("Failed to open file: %s", path);
        finish();
    }

    fseek(file, 0, SEEK_END);
    usize len = ftell(file);
    fseek(file, 0, SEEK_SET);

    *data = static_cast<char *>(calloc(len + 1, sizeof(char)));
    if (!*data) {
        info("Failed to allocate\n");
        finish();
    }

    if (fread(*data, 1, len, file) != len) {
        info("Failed to read file\n");
        finish();
    }
    (*data)[len] = '\0'; // null terminate
    return len;
}
