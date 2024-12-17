#pragma once

#include <cassert>

#ifdef DEBUG
#define when_debug(...) __VA_ARGS__
#else
#define when_debug(...)
#endif

#ifdef _MSC_VER
#define unreachable() __assume(0);
#else
#define unreachable()                                                                                                  \
    assert(false && "Unreachable");                                                                                    \
    __builtin_unreachable();
#endif
