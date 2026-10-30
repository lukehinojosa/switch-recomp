/* The game interface (include/hk/game.h) from C: the register prefix every
 * game's context starts with has the same layout in C and C++ (see
 * game_abi_check.cpp), and a game description builds from plain C. */
#include "hk/game.h"

#include <stddef.h>
#include <stdio.h>

_Static_assert(offsetof(hk_cpu_prefix, x) == 0, "x0 first");
_Static_assert(offsetof(hk_cpu_prefix, sp) == 248, "sp after x30");
_Static_assert(offsetof(hk_cpu_prefix, v) == 256, "vectors after sp");
_Static_assert(sizeof(hk_cpu_prefix) == 768, "prefix size");
_Static_assert(_Alignof(hk_cpu_prefix) == 16, "prefix alignment");

size_t game_abi_cpp_prefix_size(void);
size_t game_abi_cpp_vector_offset(void);
size_t game_abi_lift_vector_offset(void);

static void nothing(void *cpu) { (void)cpu; }

static const hk_function functions[] = {{0x7100000000ull, nothing}};
static const hk_module modules[] = {
    {sizeof(hk_module), HK_RELOCATE_SELF, "main", {0}, 0x7100000000ull, 0x1000, functions, 1, NULL, 0, 1, 0},
};
static hk_guest_fn *original;
static const hk_hook hooks[] = {{"_ZN2nn4pctl19IsRestrictionEnabledEv", 0, nothing, &original}};

int main(void) {
    hk_game game = {0};
    game.struct_size = sizeof game;
    game.abi_major = HK_GAME_ABI_MAJOR;
    game.abi_minor = HK_GAME_ABI_MINOR;
    game.program_id = 0x0100000000001000ull;
    game.title = "test";
    game.cpu.size = sizeof(hk_cpu_prefix) + 64;
    game.cpu.alignment = 16;
    game.memory.kind = HK_MEMORY_FIXED_BASE;
    game.modules = modules;
    game.module_count = 1;
    game.hooks = hooks;
    game.hook_count = 1;
    int failures = 0;
    if (game_abi_cpp_prefix_size() != sizeof(hk_cpu_prefix) || game_abi_cpp_vector_offset() != 256) {
        fprintf(stderr, "C++ sees a different prefix\n");
        ++failures;
    }
    if (game_abi_lift_vector_offset() != 256) {
        fprintf(stderr, "rt::Cpu (tools/lift.py) does not start with the prefix\n");
        ++failures;
    }
    if (!failures)
        printf("game_abi_test: %s, %u module(s), %u hook(s)\n", game.title, (unsigned)game.module_count,
               (unsigned)game.hook_count);
    return failures != 0;
}
