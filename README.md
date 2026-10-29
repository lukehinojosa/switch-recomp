# switch-recomp

Research into statically recompiling Nintendo Switch system modules (the
userland sysmodules, not the kernel) and running them under a native runtime,
starting with the parental-control module MK8D talks to. See the
[design draft](docs/recompiled-sysmodule-design.md).

This repository holds authored source only. Firmware, keys and anything
generated from them are supplied and kept locally, and are never committed.

Licensed under the GNU General Public License, version 3; see
[LICENSE](LICENSE).

## Kernel

`src/kernel/` is a host-side Horizon kernel subset in C++20: named ports,
sessions, handle tables and HIPC message copy between guest processes, in
one host process or across a link to a kernel in another
(`Kernel::AttachLink`). Guest code calls it through `hk_svc` in
`include/hk/svc.h`. Windows hosts only, for now.

Tests: `ipc_test` (two guest processes, one host process, including
buffers), `sync_test` (threads, events and guest mutexes and condition
variables), `native_test` (native CMIF services, domains and `sm`) and
`transport_test`, which launches `echo_host` as a separate process.

```
cmake -S . -B out/msvc -G "Visual Studio 17 2022" -A x64
cmake --build out/msvc --config Debug
ctest --test-dir out/msvc -C Debug --output-on-failure
```

CLion's default CMake profile builds the same targets.

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
C++ against `include/rt/ops.h` and reports anything it could not lift.
`tools/difftest.py <relocated.elf> <work dir>` checks the lifter against
unicorn instruction by instruction; it needs `capstone`, `unicorn` and
`clang++` on `PATH`.

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

Set `RT_TRACE=1` to log supervisor calls; lift with `--track-pc` to get the
guest PC and a backtrace on faults. `RT_BOOT_MODE` sets the boot mode the
`pm:bm` stub reports (default 1, maintenance), and `RT_PROBE=1` checks that
the module serves `pctl`, then exits.

`nca.py --extract <folder>` writes the matching modules' ExeFS files (`main`,
`main.npdm`) for analysis. Keep that folder outside the repository or under an
ignored path.
