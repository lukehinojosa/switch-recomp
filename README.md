# switch-recomp

Research into statically recompiling Nintendo Switch system modules (the
userland sysmodules, not the kernel) and running them under a native runtime,
starting with the parental-control module MK8D talks to. See the
[design draft](docs/recompiled-sysmodule-design.md). The [plan](plan.md) sets
the wider direction: a native host that runs the Switch's recompiled userland
and any recompiled game, with a roadmap.

This repository holds authored source only. Firmware, keys and anything
generated from them are supplied and kept locally, and are never committed.

Licensed under the GNU General Public License, version 3; see
[LICENSE](LICENSE).

## Kernel

`src/kernel/` is a host-side Horizon kernel subset in C++20: named ports,
sessions, handle tables, events and HIPC message copy between guest
processes, in one host process or across a link to a kernel in another
(`Kernel::AttachLink`); session ends and readable events cross the link.
Guest code calls it through `hk_svc` in `include/hk/svc.h`. Windows and Linux
hosts (`src/kernel/platform_win32.cpp`, `platform_posix.cpp`).

Tests: `ipc_test` (two guest processes, one host process, including
buffers), `sync_test` (threads, events and guest mutexes and condition
variables), `native_test` (native CMIF services, domains and `sm`),
`transport_test`, which launches `echo_host` as a separate process (events
crossing the link included), and `game_abi_test` (the game interface's
layout from C and C++). `roundtrip_bench` measures a request in one kernel
and across a link, and optionally a real module's command.

```
cmake -S . -B out/msvc -G "Visual Studio 17 2022" -A x64
cmake --build out/msvc --config Debug
ctest --test-dir out/msvc -C Debug --output-on-failure
```

CLion's default CMake profile builds the same targets. On Linux, configure
with any generator; the same tests run (checked with GCC 13 and Clang 18).

## Game interface

[include/hk/game.h](include/hk/game.h) is the C interface a recompiled game
and the host meet at: the game's CPU context layout, how its code reaches
guest memory, its modules and its hooks, and the host's functions it calls.
See [docs/game-interface.md](docs/game-interface.md).

## Tools

`tools/nca.py` reads system NCAs from a local firmware folder and reports each
program sysmodule's ExeFS files and the services its NPDM lets it host and use.
Requires Python 3 and `pycryptodomex`.

```
python tools/nca.py --keys <prod.keys> --firmware <firmware folder> --host pctl
```

`tools/nso.py <main> <out.elf>` decompresses an NSO, applies its relative
relocations and writes an AArch64 ELF that Ghidra loads directly (default base
`0x7100000000`).

`tools/ghidra/` holds headless Ghidra scripts: `ServiceRefs.java` reports which
functions name each service and whether startup reaches them by direct calls;
`Decompile.java` prints decompiled C for given addresses. Run them with
`analyzeHeadless <project dir> <name> -import <elf> -scriptPath tools/ghidra
-postScript ServiceRefs.java <service> ...`.

`tools/lift.py <relocated.elf> <out dir>` statically recompiles a module to
C++ against `include/rt/ops.h` and reports anything it could not lift. A
title's modules lift together into one function table: `nso.py --exefs
<ExeFS folder> <out>` lays them out as Horizon's loader does (rtld, main,
subsdk0 to subsdk9, sdk, one after another) and writes each as
`<name>.elf` and `<name>.load.elf`, with `layout.txt` and a copy of
`main.npdm`, then `lift.py <out>/rtld.elf <dir> --module <out>/main.elf
--module ...` lifts them in that order, starting the process at rtld.
The generated files each hold 128 KB of guest code (`--file-span`) and
declare only what they call, and unchanged files are left alone, so after a
lifter change the build recompiles only the files whose code moved.
`tools/difftest.py <relocated.elf> <work dir> [--simd | --integer]` checks
the lifter against unicorn instruction by instruction (`--simd` and
`--integer` split a module's words in two); it needs `capstone`, `unicorn`
and `clang++` on `PATH`.

To run a lifted module, configure with `-DSWITCH_RECOMP_LIFTED=<out dir>` and
build `module_host`, then pass it the unrelocated image
(`nso.py --no-relocate`), which the module relocates itself:

```
python tools/nso.py extracted/<module>/main out/<module>.elf
python tools/nso.py --no-relocate extracted/<module>/main out/<module>.load.elf
python tools/lift.py out/<module>.elf out/lifted/<module>
cmake -S . -B out/msvc-<module> -G "Visual Studio 17 2022" -A x64 -DSWITCH_RECOMP_LIFTED=<abs path>/out/lifted/<module>
cmake --build out/msvc-<module> --config Release --target module_host
out/msvc-<module>/Release/module_host.exe out/<module>.load.elf
```

A whole title's lift is far larger (MK8D: 446 MB of C++). Build it with
Ninja and clang-cl from a Visual Studio developer prompt, which compiles one
file per core (about two minutes for MK8D on 20 threads); the Visual Studio
generator runs only a few compiles at a time:

```
cmake -S . -B out/clang-<title> -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DSWITCH_RECOMP_LIFTED=<abs path>/out/lifted/<title>
cmake --build out/clang-<title> --target module_host
```

A lifted title runs as an application with `--title`, which loads every
module from the `nso.py --exefs` folder and reads the program id and main
thread from its `main.npdm`; `--romfs` gives `fsp-srv` the RomFS image to
serve (`nca.py --romfs`, below):

```
out/clang-<title>/module_host.exe --title <exefs layout folder> --romfs <romfs image>
```

In that mode the host adds the services an application asks for on its way
to its first frame (`src/services/application.cpp`, `nvdrv.cpp`, `vi.cpp`):
`am` through `appletOE`, `apm`, `aoc:u`, `pctl`, `set`, `hid` with no
controllers, `nvdrv` with no GPU behind it, which records what the title
submits, and `vi` as a display that shows nothing.
[docs/title-host.md](docs/title-host.md) lists what MK8D calls.

Recompiled sysmodules run beside it, each in a `module_host` of its own
built with its lift: `--sysmodule <host> <module.load.elf>`, repeated, starts
each as a linked child. The parent's kernel relays between its links, so the
children reach each other's services as well as the parent's. The services a
module's `main.npdm` hosts replace the stubs of the same names everywhere, and
the parent serves `pm:info`, `pgl`, `ncm` and `lr` for every process;
`--content <folder>` (from `nca.py --content-index <folder> [package...]`)
gives `ncm` and `lr` the firmware's content metas and those of the user's
packages. `--system-data <folder>` (from
`nca.py --system-data <folder> all`) and `--calibration <file>` (from
`tools/calibration.py <file>`, a blank CAL0 image) give `fsp-srv` the
firmware's system data archives and the console's calibration partition;
both pass on to the children. Each child's output is prefixed with its
module's name. [docs/system-processes.md](docs/system-processes.md) records
running `settings`, `account` and `ns` this way.

Set `RT_TRACE=1` to log supervisor calls, and the commands a recompiled
server receives and the results it replies with; lift with `--track-pc` to
get the guest PC and a backtrace on faults, and set `RT_PEEK=<address>,...`
to print those guest words with them. `RT_BOOT_MODE` sets the boot mode the
`pm:bm` stub reports (default 0, a normal boot; 1 is maintenance), and `RT_PROBE=1` checks that
the module serves `pctl`, then exits.

`nca.py --extract <folder>` writes the matching modules' ExeFS files (`main`,
`main.npdm`) for analysis. Keep that folder outside the repository or under an
ignored path. `nca.py --keys <prod.keys> --nacp <game.nsp> <out>` writes a
game's `control.nacp` (its application control data) from the NSP's Control
NCA, and `--exefs <game.nsp> <folder>` its program's ExeFS, decrypted with the
title key from the NSP's own ticket. `--romfs <game.xci|nsp> <out> [--update
<update.nsp>]` writes the game's RomFS image, with the update's patch (BKTR)
section applied over it when given, and `--firmware <folder> --system-data
<folder> <id>...` writes system-data archives (fonts, Mii data) as RomFS
images, or every one of them for `all`. `--content-index <folder>
[package...]` writes the firmware's content metas, and those of NSPs and
XCIs as installed, in the form `ncm` keeps them, for `module_host
--content`.
Both check every block against the section's IVFC hashes as they write.

`module_host --link <read> <write>` serves over a link to a parent process,
which reaches the ports the module registers; `--application <pid> <program
id> <version> <control.nacp>` makes `arp:r` report that process as a running
application. With `--title`, `--launch` starts the title only when the
recompiled `ns` launches it: the host asks `ns` as `am` does (see
[docs/system-processes.md](docs/system-processes.md)), which does not get
through yet. The `module_client` library (`src/client/`) is the parent's side:
it starts the host, connects to its ports and sends CMIF requests. With a
lifted `pctl`, `pctl_shadow` uses it to make the requests Mario Kart 8 Deluxe
makes and compare the replies with mk8-recomp's verified service:

```
out/msvc-pctl/Release/pctl_shadow.exe out/msvc-pctl/Release/module_host.exe out/pctl.load.elf <control.nacp> [boot mode]
```

`hk_module_client.dll` offers the same client through a C interface
(`include/hk/module_client.h`), for titles written in C or built with another
toolchain; it shares no C++ runtime with its caller. Events a module returns
come back as `hk_module_event`, mirrors of the module's own event that a
title can wait on, clear and watch. `client_c_test` drives it from C.
