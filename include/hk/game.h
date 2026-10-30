/* The game interface, version 1: what a recompiled game gives the host and
 * what the host gives it back. Plain C, so that a game can be built by any
 * recompiler and toolchain and loaded as a plugin. See
 * docs/game-interface.md for the rules each part follows.
 *
 * A game exports one function, hk_game_entry. The host calls it with its own
 * function table and gets back the game's description: its CPU context
 * layout, how its code reaches guest memory, its modules and its hooks.
 */
#ifndef HK_GAME_H
#define HK_GAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HK_GAME_ABI_MAJOR 1
#define HK_GAME_ABI_MINOR 0

#if defined(_WIN32)
#define HK_GAME_EXPORT __declspec(dllexport)
#else
#define HK_GAME_EXPORT __attribute__((visibility("default")))
#endif

/* ---- CPU context ------------------------------------------------------------
 * Every game's context starts with this prefix: the general registers with
 * sp after x30, then the vector registers, 16-byte aligned. What follows is
 * the recompiler's own, described by hk_cpu_layout. */
typedef struct hk_v128 {
    uint64_t lo, hi;
} hk_v128;

typedef struct hk_cpu_prefix {
    uint64_t x[31];
    uint64_t sp;
#if defined(__cplusplus)
    alignas(16) hk_v128 v[32];
#else
    _Alignas(16) hk_v128 v[32];
#endif
} hk_cpu_prefix;

/* Where the rest of the state the host touches lives, as byte offsets from
 * the start of the context. A width of 4 or 8 says how the field is stored. */
typedef struct hk_cpu_field {
    uint32_t offset, width;
} hk_cpu_field;

typedef struct hk_cpu_layout {
    uint32_t size;      /* the whole context; the host allocates and zeroes it */
    uint32_t alignment; /* at least 16 */
    hk_cpu_field fpcr, fpsr, tpidr, tpidrro;
    /* A pointer-sized slot the host keeps its thread object in. */
    uint32_t host_slot;
    /* HK_MEMORY_RUNTIME_BASE only: a pointer-sized slot the host fills with
     * the host address of guest address 0. */
    uint32_t membase_slot;
} hk_cpu_layout;

/* ---- Guest memory -------------------------------------------------------------
 * Guest addresses are below 2^39. The host reserves that range for the guest
 * and maps guest address a at host address base + a, where base is: */
enum {
    HK_MEMORY_FIXED_BASE = 1,   /* fixed_base, compiled into the game's code; the host maps
                                   there or refuses to start the game */
    HK_MEMORY_RUNTIME_BASE = 2, /* chosen by the host and stored in each context's membase_slot */
};

typedef struct hk_memory_model {
    uint32_t kind;
    uint32_t reserved;
    uint64_t fixed_base; /* HK_MEMORY_FIXED_BASE: 0 means guest addresses are host addresses */
} hk_memory_model;

/* ---- Code -------------------------------------------------------------------- */
typedef void hk_guest_fn(void *cpu);

typedef struct hk_function {
    uint64_t address; /* guest entry point */
    hk_guest_fn *code;
} hk_function;

typedef struct hk_symbol {
    const char *name; /* mangled, as the module exports it */
    uint64_t address;
} hk_symbol;

enum {
    HK_RELOCATE_SELF = 1,  /* the guest's own start-up code (rtld) applies relocations */
    HK_RELOCATE_DONE = 2,  /* the code was generated from a relocated image */
};

/* One executable module: an NSO of the game's ExeFS, or an NRO it loads at
 * run time. The host loads its image from the user's own dump, found by
 * build id; the game carries code, never the image. */
typedef struct hk_module {
    uint32_t struct_size;
    uint32_t relocation;      /* HK_RELOCATE_* */
    const char *name;         /* "rtld", "main", "sdk", "subsdk0", or an NRO's name */
    uint8_t build_id[32];
    uint64_t base;            /* where the code expects the image */
    uint64_t image_size;
    const hk_function *functions; /* sorted by address */
    size_t function_count;
    const hk_symbol *exports; /* optional, sorted by name */
    size_t export_count;
    uint32_t loaded_at_start; /* 1 for ExeFS modules, 0 for NROs loaded through nn::ro */
    uint32_t reserved;
} hk_module;

/* ---- Hooks ----------------------------------------------------------------------
 * Native code that takes the place of a guest function, found by exported
 * name or by address. With original set, the host stores the replaced
 * function there, so the hook can call through to it. */
typedef struct hk_hook {
    const char *symbol;     /* or null, and address set */
    uint64_t address;
    hk_guest_fn *replacement;
    hk_guest_fn **original; /* optional */
} hk_hook;

/* ---- What the host provides ------------------------------------------------------
 * Called from generated code on a guest thread. */
typedef struct hk_host_api {
    uint32_t struct_size;
    uint32_t abi_major, abi_minor;
    uint32_t reserved;
    /* An indirect call or tail call to a guest address (BLR, BR). */
    void (*call)(void *cpu, uint64_t target);
    /* SVC #imm at pc; arguments and results in the context's registers. */
    void (*svc)(void *cpu, uint32_t imm, uint64_t pc);
    /* CNTPCT_EL0: the 19.2 MHz counter. */
    uint64_t (*counter)(void);
    /* An instruction the recompiler could not translate, or a jump outside a
     * table's cases; does not return. */
    void (*trap)(void *cpu, uint64_t pc, const char *what);
    /* The guest address of an exported symbol in any loaded module, or 0. */
    uint64_t (*symbol)(const char *name);
} hk_host_api;

/* ---- What the game provides -------------------------------------------------------- */
typedef struct hk_game {
    uint32_t struct_size;
    uint32_t abi_major, abi_minor; /* HK_GAME_ABI_* the game was built against */
    uint32_t reserved;
    uint64_t program_id;
    const char *title;           /* for logs */
    hk_cpu_layout cpu;
    hk_memory_model memory;
    const hk_module *modules;
    size_t module_count;
    const hk_hook *hooks;
    size_t hook_count;
} hk_game;

/* Exported by every game. Returns null if the host's ABI is not one the game
 * supports (a different major version). */
typedef const hk_game *hk_game_entry_fn(const hk_host_api *host);
HK_GAME_EXPORT const hk_game *hk_game_entry(const hk_host_api *host);

#ifdef __cplusplus
}
#endif

#endif
