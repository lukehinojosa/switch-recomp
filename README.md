# switch-recomp

Research into statically recompiling Nintendo Switch system modules (the
userland sysmodules, not the kernel) and running them under a native runtime,
starting with the parental-control module MK8D talks to. See the
[design draft](docs/recompiled-sysmodule-design.md).

This repository holds authored source only. Firmware, keys and anything
generated from them are supplied and kept locally, and are never committed.

## Kernel

`src/kernel/` is a host-side Horizon kernel subset in C++20: named ports,
sessions, handle tables and HIPC message copy between guest processes, in
one host process or across a link to a kernel in another
(`Kernel::AttachLink`). Guest code calls it through `hk_svc` in
`include/hk/svc.h`. Windows hosts only, for now.

Tests: `ipc_test` (two guest processes, one host process) and
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

`nca.py --extract <folder>` writes the matching modules' ExeFS files (`main`,
`main.npdm`) for analysis. Keep that folder outside the repository or under an
ignored path.
