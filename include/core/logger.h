#pragma once

#include "core/debug.h"

#include <stdio.h>

#define info(fmt, ...) when_debug(fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__));

#define warn(fmt, ...) when_debug(fprintf(stdout, "[WARN] " fmt "\n", ##__VA_ARGS__));

#define error(fmt, ...) when_debug(fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__));
