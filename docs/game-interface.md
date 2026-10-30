# Game interface, version 1

Status: draft, 2026-10-30. The header is
[include/hk/game.h](../include/hk/game.h); this page gives the rules behind
it. It is milestone 3 of the [plan](../plan.md)'s phase 1.

A recompiled game is code generated from the user's own dump, plus that
game's patches and enhancements. The host is everything else: the kernel, the
services, the graphics layer and the platform. The interface between them is
plain C, so a game can come from any recompiler and toolchain and be loaded as
a plugin (a DLL or shared library), or linked in statically.

## The handshake

A game exports one function:

```c
const hk_game *hk_game_entry(const hk_host_api *host);
```

The host calls it once, before any guest code runs, with its function table.
The game keeps the table and returns its description, or null if the host's
major version is one it does not support. Every struct starts with its size
and every table carries the version it was built against, so a minor version
can add fields at the end without breaking either side.

## The CPU context

Each recompiler keeps its own context struct; the three looked at so far all
lay one out differently. Version 1 fixes only the part they already share:

| Offset | Field |
| --- | --- |
| 0 | `x[31]`: x0 to x30 |
| 248 | `sp` |
| 256 | `v[32]`: the vector registers, 16 bytes each, 16-byte aligned |

Everything after byte 768 belongs to the recompiler: flags, a debugging PC,
the exclusive monitor, caches. The game's `hk_cpu_layout` tells the host the
whole size, and where the fields the host has to reach are: `fpcr`, `fpsr`,
`tpidr` and `tpidrro`, each with its width (4 or 8 bytes), a pointer-sized
slot for the host's thread object, and (with a runtime memory base) the slot
for the base. The host allocates contexts of that size and alignment, zeroes
them, and sets these fields when it creates a thread.

Arguments and results follow the AArch64 procedure call standard (x0 to x7,
v0 to v7), so a host function standing in for a guest function reads and
writes the prefix only.

## Guest memory

Guest addresses are below 2^39, as on the console. The host reserves that
range and maps guest address `a` at host address `base + a`. The game says how
its code finds `base`:

- **Fixed** (`HK_MEMORY_FIXED_BASE`): a constant compiled into the code, 0 when
  guest addresses are host addresses. Fastest: a guest pointer is a host
  pointer. The host maps the guest there or refuses to start the game, for
  example on a platform that keeps part of that range for itself.
- **Runtime** (`HK_MEMORY_RUNTIME_BASE`): the host picks `base` and writes it
  into each context's `membase_slot`; the code adds it to every access.

Nothing is translated page by page in either case: guest memory is host
memory.

## Code and modules

The game describes each executable module it was generated from: the ExeFS
modules (`rtld`, `main`, `sdk`, `subsdk*`) and every NRO it loads at run time
through `nn::ro`, lifted ahead of time since nothing is compiled while the game
runs. A module gives its build id, the address its code expects, its size, and
a table of guest entry points and their native functions, sorted by address.

The game carries code, never images. The host loads each image from the
user's dump by build id, so the game's files hold nothing from the
cartridge beyond what its code was generated from. Relocation is either done
by the guest's own start-up code (`HK_RELOCATE_SELF`, what Horizon's `rtld`
does for every module) or already applied when the code was generated
(`HK_RELOCATE_DONE`).

## What the host provides

Generated code leaves itself through four calls in `hk_host_api`:

- `call`: an indirect call or branch to a guest address (`BLR`, `BR`), found
  through the module tables.
- `svc`: a supervisor call, with its arguments and results in the context.
- `counter`: `CNTPCT_EL0`, the 19.2 MHz counter, read from the host's clock.
- `trap`: an instruction the recompiler could not translate, or a jump
  outside a table's cases; it does not return.

`symbol` finds an exported guest symbol, for hooks and for native code that
calls back into the game.

## Hooks

A hook puts native code in place of a guest function, found by its exported
(mangled) name or by address. With `original` given, the host stores the
replaced function there so the hook can call through. Hooks by name are how
the [replacement library](../plan.md#replacement-library) replaces SDK and NVN
functions; hooks by address are for a recomp project's own patches.

## Checked against three recompilers

| | lift.py (switch-recomp) | WindowSmash | mk8-recomp |
| --- | --- | --- | --- |
| Context prefix | matches, since this change (vectors moved up to follow sp) | matches (`x[31]`, `sp`, `v[32]`) | matches (`x[32]`, with sp as x31, then `v[32]`) |
| fpcr, fpsr | 8 bytes each | 4 bytes each | 8 bytes each |
| Host's thread slot | `host` | `thread` | none yet: needs a field |
| Memory | runtime base (`mem`), masked to 39 bits | fixed base (`RT_MEMBASE`, 0 on Windows) | fixed base (`NX_BASE`, guest pointers are host pointers) |
| Leaving generated code | `rt::Call`, `Svc`, `CounterTicks`, `Unimplemented` | `rt_lookup`, kernel SVC entry, HLE table | `nx::call`, `svc`, `mrs`, `unimpl` |
| Module table | `rt_functions`, `rt_module_entry` | `RtModule` (functions, exports, imports, relocations, build id) | per-module tables in `module.h` |
| Native replacements | none yet | `HLE(sym)` by name, `HLE_WRAP(addr)` by address | the runtime's own HLE files |

Each recompiler fits by adding a small shim in its generated game: its own
call, SVC, counter and trap entry points forward to the `hk_host_api` table,
and its module tables are copied into `hk_module` entries. None of the three
needs its generated code changed, apart from mk8-recomp's context gaining a
host slot. `HLE(sym)` and `HLE_WRAP(addr)` map directly onto hooks by name
and by address.

## Not in version 1

- Run-time code generation: Switch games do not do it, and the interface
  assumes every guest function was lifted ahead of time.
- AArch32 games: the context and the counter are AArch64 only.
- Exceptions crossing between guest and host code (the C++ `setjmp`/`longjmp`
  and unwinding schemes each recompiler uses stay inside the game).
- Graphics: NVN calls reach the host through hooks by name; the graphics
  layer's own interface comes with phase 3.
