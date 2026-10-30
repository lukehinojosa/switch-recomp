# switch-recomp plan

Status: draft, 2026-10-30. This plan sets the direction for the whole
project. The [sysmodule design draft](docs/recompiled-sysmodule-design.md)
stays the detailed record of the first track (recompiled `pctl`), which is now
phase 0 of the roadmap below.

## Vision

switch-recomp is a native host for statically recompiled Nintendo Switch
games: the Switch operating system's userland, recompiled and run as a native
application, with the kernel and the hardware drivers replaced by native host
code. A game's recomp project plugs into it and gets the OS, the services, the
GPU layer and every supported platform without writing them again.

It is not an emulator. A recomp is meant to run native machine code, in native
memory, with hardware-accelerated graphics. If the host cannot hit those marks,
there is no reason to use it over an emulator.

## Principles

1. **Native or nothing.** Nothing is simulated: no interpreted CPU, no
   modelled clocks, no emulated MMU. A rule that makes games behave correctly
   belongs in the host only if it is free, or nearly free, in native terms
   (matching floating-point modes, zeroed pages, host time read as a 19.2 MHz
   counter). Anything that needs simulation is out; if a game depends on it,
   its recomp project patches the game instead.
2. **Recompile userland; replace the kernel and the drivers.** Horizon is a
   microkernel, so almost all of the OS is userland processes, its hardware
   drivers included. The logic processes are recompiled from the user's
   firmware. The kernel is our host kernel. Processes that drive hardware
   (GPU, input, audio, display, storage, Bluetooth, power) are replaced with
   native implementations on host APIs.
3. **Prefer the firmware's own code for logic.** A recompiled module behaves
   like the console's by construction. Native implementations are for hardware
   and for hot paths, and each one is checked against the recompiled module
   for the same service wherever both exist (the way `pctl` was shadowed).
4. **No game checks in the host.** No `if (program_id == ...)` anywhere in
   host code. Shared fixes are keyed by library and version or by cause, never
   by game.
5. **Every GPU vendor.** NVIDIA, AMD, Intel and Apple Silicon. Switch games
   were written for an NVIDIA GPU, so the other vendors are where problems
   appear; the host is tested on all of them.
6. **Fast shader precompilation, the same for every game.** One translator,
   run when a recomp is built, for every title. First launch costs a driver
   compile per shader, in parallel, and never a stall or a skipped draw.
7. **Authored source only.** Firmware, games, keys and everything generated
   from them are supplied and kept by the user and never committed or
   distributed. Work comes from the binaries and their observed behaviour,
   never from leaked SDK material. A legal and provenance review comes before
   any public release.

## Who does what

| | Host (this project) | Recomp project (per game) |
| --- | --- | --- |
| Code | The recompiler and the game interface | The game's lifted code, built from the user's dump |
| OS | Kernel, services, system processes, applets | Nothing |
| Correctness | Native behaviour that is free to match; shared replacements, each verified | Patches for game code that depends on console timing or other behaviour the host will not simulate |
| Graphics | NVN on Vulkan, shader pipeline, vendor fallbacks | Nothing beyond its enhancements |
| Enhancements | Mechanisms: render scale, aspect ratio, frame pacing and interpolation hooks, input remapping, function hooks | Higher frame rates, resolution, widescreen, UI, mods |
| Platforms | Windows, Linux, macOS, later Android | Nothing |

A bug in an unmodified game is the host's. A bug that appears only with an
enhancement belongs to the recomp project.

## Architecture

From the bottom up.

### Platform layer

Threads, memory reservation, files, processes and pipes, the window, input
devices and audio output. Today only Windows exists
(`src/kernel/platform_win32.cpp`). Linux comes next, then macOS, then Android.

### Host kernel (`src/kernel/`, done in part)

Horizon's supervisor calls on host primitives: handles, ports, sessions,
events, guest mutexes and condition variables, IPC message copy with handle
translation, and the link between host processes. Games and modules call it
through the C interface in `include/hk/svc.h`.

### Process model

On desktop, each system process runs in its own host process, connected by
the link (the design draft's decision; `module_host` and `module_client` are
the pieces). Platforms that cannot start child processes (iOS, consoles, and
likely Android in practice) need an in-process mode in which every module
shares the host process with separate guest address spaces. The process model
must keep both possible.

### Guest memory

Lifted code reaches guest memory as a base pointer plus the address masked to
Horizon's 39-bit address space (`rt::HostAddress` in `include/rt/ops.h`): an
AND and an ADD, no translation tables. That is native memory. Mapping the
guest range at the same host addresses, so pointers need no base at all, is a
possible later optimisation, not a requirement.

### Services

CMIF, domains and `sm` (`src/kernel/`), with native services written against
the same framework as recompiled modules.

### System processes

| Group | Processes | Approach |
| --- | --- | --- |
| Lifecycle | `am` (applet manager), `pm`, `ldr` | `am` recompiled; process creation and loading native |
| Content and storage | `fs`, `ncm`, `lr` | Native, over host files holding the user's decrypted content |
| System logic | `ns`, `account`, `settings`, `time`, `pctl`, `friends` (offline), `bcat`, `psc`, `arp`, `pdm` | Recompiled |
| Hardware | `nvservices`, `hid`, `audio`, `vi`, `bluetooth`, `pcv`, `psm` | Native on host APIs (Vulkan, SDL or similar, host audio, the host window) |
| Network | `nifm`, `bsd`, `ssl`, `npns` | Native: "no network" at first, host sockets later |

The list is a starting point; each title's first run shows which processes it
really needs, as MK8D's did for `pctl`.

### Graphics

- **NVN on Vulkan is the main path.** Games get NVN's functions from its
  loader by name (`nvnBootstrapLoader`, then `nvnDeviceGetProcAddress`), so
  the host hands back its own implementations at that one point, and every
  name a game asks for is known.
- **The game's own NVN code is the reference.** It is linked into every game
  and recompiled with it; running it down to `nvdrv` and decoding the Maxwell
  commands is a debugging aid and a comparison target, not the main path.
- **Behaviour below the API** that games rely on (tiled texture memory, their
  own command memory, raw GPU addresses, their own synchronisation) is
  honoured where games use it.
- **Vendors.** Every format has a capability check and a fallback (`D24S8`
  depth and some vertex formats on AMD, ASTC everywhere except Apple, decoded
  on the GPU). Validation and synchronization validation layers run in
  testing and their warnings are bugs. On Apple, geometry shaders and
  transform feedback are done another way, such as compute.
- **Vulkan everywhere** (MoltenVK on Apple). WebGPU stays in the backlog as a
  possible second backend.

### Shader pipeline

1. **Discover.** Scan RomFS and the binaries for compiled Maxwell programs by
   their shader header; no play-and-dump passes.
2. **Translate when the recomp is built.** Maxwell to SPIR-V by a native C++
   translator, parallel across all cores. State only seen at draw time
   (integer outputs, vertex formats, texture types) becomes specialization
   constants or a small set of variants. Results are cached by shader hash, so
   shaders shared between games are translated once.
3. **Compile at first launch.** The driver's compile depends on the user's GPU
   and driver and cannot be shipped. Graphics pipeline libraries, extended
   dynamic state or shader objects bring it to about one compile per shader,
   not one per shader and state; everything compiles in parallel at first
   launch into a persistent pipeline cache.
4. **Never stall.** A pipeline that is not ready yet draws with a generic
   fallback shader (Dolphin's ubershaders are the model) while the specialised
   one compiles in the background. Drivers without the extensions build full
   pipelines in the background instead.

### Content

Reading NCAs, ExeFS, RomFS with update patches (BKTR), NACP and system data.
It exists today as `tools/nca.py`; the parts a running host needs (RomFS and
system data at run time) move into C++.

### Recompiler and game interface

- **The recompiler** is `tools/lift.py`, which lifts AArch64 to C++ against
  `include/rt/ops.h` and is checked instruction by instruction against
  unicorn. It must scale from a sysmodule to a full game: `main`, `sdk` and
  every `subsdk`, plus any NRO a game loads at run time through `nn::ro`
  (lifted ahead of time, since nothing is compiled while running).
- **The game interface** is a versioned C ABI that every recomp targets,
  whatever recompiler produced it: the guest CPU state and memory model, the
  supervisor call entry (`hk_svc`), the entry point, and the hook API.
  Recomps built with other recompilers (WindowSmash's, mk8-recomp's) can
  target it too.

### Replacement library

Shared code is replaced once, for every game that contains it:

1. **SDK and NVN by name.** `main` links to the `sdk` module dynamically, so
   its functions are exported by name; replacements are keyed by name and SDK
   version.
2. **Middleware by fingerprint.** Engine code in `main` has no names, so it is
   matched by a hash of each function's instructions with addresses masked,
   plus its calls.
3. **Every replacement is verified** against the original code, which is
   still present and recompiled in the same binary: same inputs, compare
   results. A fingerprint match in a new game is verified automatically
   before it is trusted.

A game's manifest records what matched (SDK version, middleware found) and
which enhancements its project adds, not patches written for it.

### Developer interface

What a recomp project uses for enhancements: render resolution scale and
aspect ratio, frame pacing control with a hook for interpolated frames, input
remapping and extra controller types, function replacement and wrapping, and
running the game's clock at a different rate.

### Test harness

- Scripted input, as `SSBU_INPUT` does in WindowSmash.
- Frame hashes compared with reviewed frames, on each GPU vendor.
- Automatic reports of missing shaders, unhandled commands, unmatched NVN
  names and service mismatches.
- Shadow comparison of native services against recompiled modules.

Running a new game becomes one run that produces a report.

## Where things stand

- **Done (phase 0, milestones 1 to 3 of the design draft):**
  - the host kernel and the cross-process link;
  - the lifter with differential testing;
  - `module_host` running a recompiled `pctl` through start-up in both boot
    modes;
  - `module_client` and its C DLL;
  - `nca.py`'s content tools;
  - a clean shadow of MK8D's `pctl` calls in mk8-recomp, and SSBU in
    WindowSmash using the recompiled module online.
- **Not started:** the game interface, a game running on the host, graphics,
  other platforms.
- **Carried over from the design draft:** milestone 4 (reviewed frames)
  becomes part of the test harness; milestone 5's round-trip measurement and
  copied handles across the link (`pctl` command 1432's event) move into
  phase 1.

## Roadmap

Each milestone ends on an exit check. Phases 2 and 3 can run side by side once
phase 1 is done.

### Phase 0: recompiled sysmodule research (done)

Milestones 1 to 3 of the design draft. Proved the kernel, the link, the
lifter and serving a real game's requests from recompiled firmware.

### Phase 1: foundations

1. **Events across the link.** Copied handles reach the other process, so
   `pctl` 1432's event can be waited on by the title. *Exit:* a test waits on
   an event signalled by a module in another process; MK8D's shadow includes
   1432.
2. **Round-trip cost.** Measure a request across the link and in one process.
   *Exit:* numbers recorded, and a decision on which services must run in
   process.
3. **The game interface, version 1.** Write the C ABI down: CPU state,
   memory, supervisor calls, entry point, hooks. *Exit:* a header and a short
   spec, reviewed against what `lift.py`, WindowSmash and mk8-recomp each
   need.
4. **The first game on the host.** Lift a game with `lift.py` (all of its
   modules) and start it on the host kernel and `sm`, with only the services
   it asks for before its first frame. *Exit:* the game reaches its first GPU
   submission with no fault, and every service it touched is listed.
   Recommended title: MK8D, since its services are mapped, mk8-recomp's
   verified services are a reference, and its RomFS and system data already
   build.
5. **Linux platform layer.** *Exit:* every existing test passes on Linux
   with GCC and Clang.

### Phase 2: the operating system

1. **Lifecycle.** `am` recompiled, process start and loading native, so a
   game is launched the way the console launches it. *Exit:* the phase 1
   game starts through `am`.
2. **Native hardware services.** `hid` (host input), `audio` (host output),
   `vi` (the host window), `fs` (host files). *Exit:* the game takes input
   and plays audio through them.
3. **System logic.** Bring up `ns`, `account`, `settings`, `time` and the rest
   as the game asks for them, recompiled. *Exit:* no hand-written stub left
   on the game's start-up path except hardware and network.
4. **In-process mode.** All modules in one host process. *Exit:* the same
   game runs in both modes with the same results.

### Phase 3: graphics

1. **Native shader translator.** Discovery by scan, Maxwell to SPIR-V in C++,
   parallel, cached by hash. *Exit:* every shader in MK8D's files is found and
   translated with no game run, faster than the Ryujinx harness.
2. **NVN on Vulkan.** Implement the names the first game asks for. *Exit:*
   the game renders its title screen, and its frames match the reference
   (the game's own NVN through `nvdrv`) on that scene.
3. **Pipeline strategy.** Pipeline libraries, dynamic state, shader objects,
   a persistent cache, the fallback shader. *Exit:* first launch compiles
   every shader with no stall in play; later launches compile nothing.
4. **Every vendor.** Format fallbacks, validation clean, tested on NVIDIA,
   AMD, Intel and Apple (MoltenVK). *Exit:* reviewed frames match on all
   four.

### Phase 4: platforms

1. **macOS** (MoltenVK, Apple Silicon). *Exit:* the first game runs.
2. **Android**, in-process mode. *Exit:* the first game runs.

### Phase 5: GUI and applets

1. **Applets.** Software keyboard, error display, controller setup, user
   picker, recompiled through the same pipeline as games. *Exit:* a game
   that opens the keyboard gets it.
2. **HOME menu.** `qlaunch`. *Exit:* games launch from it.

### Phase 6: ecosystem

1. **Replacement library.** SDK and NVN by name, middleware by fingerprint,
   automatic verification. *Exit:* one replacement serves two games without
   change.
2. **Developer interface and manifests.** *Exit:* an enhancement (for
   example render scale) built entirely in a recomp project.
3. **Test harness.** *Exit:* a new game produces a full report in one
   unattended run.
4. **More games.** SSBU next (through WindowSmash, or OpenSmash-Ultimate once
   that merge is final), then games with different engines. *Exit:* each runs
   with no game check added to the host.
5. **Documentation for recomp developers.** *Exit:* someone outside the
   project brings up a game from the docs alone.

## Risks and open questions

- **Firmware versions.** Recompiled modules are tied to one firmware version
  (23.0.1 today). Decide whether the host supports one version or several.
- **Lifter scale.** A full game is many times larger than `pctl`; build time
  and code discovery (jump tables, indirect calls) must hold up.
- **NVN coverage and versions.** NVN changes between SDK versions, and some
  games or middleware write command buffers directly.
- **Vendor gaps.** Apple lacks geometry shaders and transform feedback;
  WindowSmash's AMD bugs show the kinds of mistakes to avoid and are worth
  studying early.
- **Process counts.** Dozens of host processes on desktop; measure the cost.
- **Game code that needs console timing.** Handled by recomp projects, so it
  needs a good hook API and clear diagnostics pointing at the cause.
- **Legal review.** Required before publishing any of this.

## Decisions so far

- C++20 inside, a C ABI at every boundary (`hk_svc`, the game interface,
  `hk_module_client`).
- Recompile the userland; replace the kernel and the hardware drivers.
- One host process per system process on desktop, with an in-process mode
  for platforms that need it.
- Vulkan as the graphics backend; NVN on Vulkan as the main path.
- No game checks in the host; nothing simulated.

## Backlog

- WebGPU as a second graphics backend.
- Host networking (sockets) behind `nifm` and `bsd`.
- Mapping guest memory at identical host addresses.
