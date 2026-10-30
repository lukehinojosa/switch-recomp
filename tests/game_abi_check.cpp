// The C++ side of game_abi_test: the game interface's register prefix as C++
// sees it, and lift.py's context (rt::Cpu) laid out on that prefix.
#include "hk/game.h"
#include "rt/ops.h"

#include <cstddef>

static_assert(offsetof(rt::Cpu, x) == offsetof(hk_cpu_prefix, x));
static_assert(offsetof(rt::Cpu, sp) == offsetof(hk_cpu_prefix, sp));
static_assert(offsetof(rt::Cpu, q) == offsetof(hk_cpu_prefix, v));

extern "C" size_t game_abi_cpp_prefix_size() { return sizeof(hk_cpu_prefix); }
extern "C" size_t game_abi_cpp_vector_offset() { return offsetof(hk_cpu_prefix, v); }
extern "C" size_t game_abi_lift_vector_offset() { return offsetof(rt::Cpu, q); }
