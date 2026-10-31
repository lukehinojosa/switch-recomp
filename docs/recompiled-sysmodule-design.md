# Recompiled system modules: design draft

Status: in progress, 2026-10-29. The analysis tools in `tools/`, milestone 1
(the kernel and cross-process link, `src/kernel/`) and milestone 2 (the
lifter, `tools/lift.py`, `module_host` and native services) are done: the
recompiled `pctl` starts in both maintenance and normal boot, registers its
four ports and answers requests. The
first host title is MK8D through the mk8-recomp runtime; this repository holds the
sysmodule work itself. This work is now phase 0 of the project
[plan](../plan.md), which carries milestones 4 and 5 into its roadmap;
milestone 5's events and round-trip cost are done (phase 1).

## Goal

Replace a hand-written service implementation with the console's own system
module (sysmodule), statically recompiled to C++ (`tools/lift.py`) and run
beside the title. The first target is the parental-control
service MK8D already opens (`pctl`, with `pctl:s`, `pctl:a` and `pctl:r`).

Success means: behind an opt-in switch, MK8D's actual `pctl` requests are
answered by the recompiled module, and every reply (result code, payload bytes,
returned objects) matches the existing verified native implementation, with no
change to the default path.

This is a research track. It does not replace the verified services, and it is
not a step toward recompiling the kernel.

## Inputs and distribution

The repository ships only authored source: the kernel extensions, the bridge
and the tests. The sysmodule binaries come from firmware the developer has
already supplied locally, the same way title modules do today. Generated C++,
objects and executables for system modules stay private and gitignored, under
the same rules as title modules. `tools/nca.py` decrypts and extracts
firmware and game content with the developer's own keys; the keys, and
everything it writes, stay local. Firmware is a separate copyrighted
input, so a legal and provenance review is a precondition for publishing any
of this source, not a follow-up.

## Current architecture

From mk8-recomp's reconstructed R371 runtime (`integrations/belmante-runtime/mk8d.patch`):

- **One process.** The kernel creates a single
  `KProcess(plat::current_process_id())`. All guest threads, handles and
  memory belong to it.
- **Services are in-process objects.** `ServiceRegistrar` maps a port name to a
  factory returning `std::shared_ptr<Service>`. `SendSyncRequest` parses the
  CMIF message into an `IpcCtx` and calls `Service::handle` synchronously on the
  calling guest thread. There is no server side: nothing ever calls
  `ReplyAndReceive`.
- **Verified services.** `pctl*` and `aoc:u` use `native_services::Endpoint`
  (`verified_services/services/router.h`). `Prepare` builds a `Reply` with no
  visible effects; `validate` runs just before the response write and `commit`
  only after it succeeds. The MK8 bridge (`mk8_verified_services.cpp`) rejects
  any A/B/X/C buffer or handle transport and stops on unimplemented commands.

The bridge is the seam this design uses. The single process is the obstacle.

## Design

### 1. Process model: one host process per sysmodule

Each recompiled sysmodule runs as its own host process (`nx-sysmodule.exe`
loading that module's generated code), started and owned by the title process.

Considered and rejected for the first step: hosting a second guest address
space inside the title process. It avoids cross-process transport but requires
the CPU context, memory accessors and handle tables to become per-process
throughout the runtime, which is a much larger change to code the performance
work depends on. Separate processes keep the title path unchanged and make
failures contained: a sysmodule crash ends that child, and the title's bridge
reports it.

Each child gets:

- its own guest address space, laid out from the module's NSO and NPDM the same
  way the title's loader does today;
- its own `KProcess`, handle table and thread set;
- the declared capabilities from its NPDM (the AOC context's NPDM admission
  code is a starting point for parsing and pinning by SHA-256).

### 2. Server-side kernel subset

A server needs SVCs the runtime does not implement yet. The minimum for a
buffer-free service:

| SVC | Use |
| :--- | :--- |
| `ManageNamedPort` (0x71) or `sm` `RegisterService` | Publish the port |
| `AcceptSession` (0x41) | Take a new client session |
| `ReplyAndReceive` (0x43) | Wait for requests, send replies |
| `CloseHandle` (0x16) | Session teardown |
| `CreateSession` (0x40) | Sub-interfaces returned as moved handles |

Plus whatever thread, synchronisation and memory SVCs the module's startup
calls. That set is unknown until the module runs; the existing behaviour of
stopping on an unimplemented SVC is the right way to discover it.

`ReplyAndReceive` is implemented in the child's kernel. The child blocks in it;
an arriving message is copied into the waiting thread's TLS, and the reply is
taken from TLS when the thread calls `ReplyAndReceive` again with the session
as the reply target.

### 3. Service manager

A small native `sm` in the title process owns the name table for the
experiment. A child registering `pctl` is recorded there. The title's existing
`ServiceRegistrar` lookup consults it only for ports enabled by
`NX_SYSMODULE_PORTS` (for example `pctl,pctl:s`); every other port keeps its
current implementation.

### 4. Transport and message copy

Each host process runs its own kernel. Two kernels are joined by one **link**
over a byte stream (on Windows, a pair of anonymous pipes); every session
between the two processes is multiplexed on it by id, rather than using a
channel per session. Named ports registered on either side are announced to
the other, so `ConnectToNamedPort` finds them.

Frames are a type, a length and a body: port registered or unregistered,
connect and its reply, request and reply (by tag), client closed and server
closed. A request carries the message words, the sender's PID and a
descriptor for each copied or moved handle.

The kernel's job during copy is translation:

- **Local copies** (both processes in one host) resolve handles to objects,
  take moved handles out of the sender, then place everything in the
  receiver. If the write fails, moved handles return to the sender.
- **Handles crossing a link** are session ends. Sending one exports it under
  an id the sender allocates (the low bit says which side allocated it); the
  receiver imports it as a new local object. A client end becomes a client
  whose requests are forwarded; a server end becomes a local server session
  whose requests arrive over the link. This is how a service returns a
  sub-interface, such as `IParentalControlService`, across processes.
- **PID descriptor.** The PID is inserted by the kernel, never taken from
  client bytes (matching `native_services::Request::process_id`). Across a
  link, the receiving kernel inserts the PID the sending kernel reported.
- **Domains.** Domain object ids are per-session state on the server side and
  pass through unchanged.
- **Buffers.** A/B/X/C buffers are out of scope for the first step: the copy
  rejects any message containing them before it is sent. `pctl` traffic from
  MK8D is scalar-only, as the existing bridge already enforces. X/C buffers can
  later be copied by value; A/B buffers need the server to see the client's
  memory, which means either shared mappings or copy-in/copy-out with a
  defined write-back point.

Each link has a writer thread, so no thread blocks on a pipe while holding
the kernel lock (two kernels writing to each other with full pipes could
otherwise deadlock). When a link's stream fails, because the peer exited or
crashed, every session across it closes: waiting clients get `SessionClosed`
and the peer's ports disappear.

Current limits, each returning `NotImplemented`: forwarding a session end that
is already remote to a third place, copying (rather than moving) a server end
across a link, and objects other than session ends (ports, events). A handle
moved in a request is consumed when the request is sent; if the peer then
fails, it is closed rather than returned.

### 5. Bridge in the title

`ForwardingService : Service` replaces the registrar's factory for enabled
ports. Its `handle(IpcCtx&)` re-serialises the request (the parser already
holds every field), sends it to the child session, waits for the reply, and
fills `IpcCtx` from it. Sub-interfaces returned by the child become new
`ForwardingService` objects bound to the returned session.

It keeps the verified bridge's rules: buffers and handle transport stop the
process, and a child exit or protocol error is fatal to the title rather than
answered with a guess.

The title does not run the HIPC layer itself. `module_client`
(`src/client/module_link.h`) gives it one: a kernel of its own holding one
client process with one thread, linked to `module_host` started as a child
process (`module_host --link`). `ModuleLink::Connect` reaches a port the
module registered through `sm`, which the link announces like any named port;
`Session::Request` builds a plain CMIF request (no domain: a title domain
object maps to one child session), sends it and returns the result, the
output words and any moved sessions as new `Session`s. Requests from
different title threads are serialized on the one client thread. The child
runs in a job that kills it when the title exits; a child that exits closes
its sessions, and later requests fail with a kernel result. The title tells
the module who it is with `--application`: its PID as the module sees it,
its program ID, version and `control.nacp`, which `arp:r` reports, as `pm`
and `ns` register an application at launch on a console.

Output comparison has to allow for one transport difference: the verified
service returns exactly the output bytes (one byte for a `bool`), while a
CMIF reply carries whole words. The comparison takes the verified bytes as a
prefix of the module's output.

### 6. Lifter and module host

`tools/lift.py` turns the relocated ELF from `tools/nso.py` into C++ against
`include/rt/ops.h`. It decodes AArch64 itself (capstone is used only to print
test failures), because the lifter must know each encoding's exact semantics
rather than an alias's operands.

- **State.** Registers, flags (as four bytes), the 32 vector registers and the
  system registers the module reads live in `rt::Cpu`. Guest memory is one host
  reservation of the 39-bit guest space; an access is `base + (address & mask)`
  and a `memcpy`, so a wild address faults inside the reservation.
- **Control flow.** Each discovered entry point becomes a host function.
  Entries are the module entry, every `BL` target, code addresses built by
  `ADR`/`ADRP`+`ADD`, and code addresses stored in data. `BL`/`BLR` are host
  calls that set x30 first; `RET` returns; a branch to another entry is a tail
  call; branches inside a function are `goto`s. A body may include code below
  its entry (reached by branches), so a function whose first block is not its
  entry begins with a `goto` to it.
- **Indirect branches.** `BR` through a recognised jump table (`ADR` base,
  `LDRB`/`LDRH` offset, `ADD ... LSL #2`, bounded by the nearest `CMP` and
  `B.HI`/`B.HS`, following register copies) becomes a `switch` over its
  targets. Every other `BR` is a tail call through the sorted address table;
  in `pctl` those are all calls through function pointers (192 sites). All
  jump tables in `pctl` are recognised.
- **Traps.** An instruction the decoder does not know becomes
  `rt::Unimplemented`, and falling off a decoded body stops the same way, so a
  partial lift builds and stops loudly. `pctl` lifts to 4,260 functions with
  no unknown instructions; the only traps are its `UDF` padding.
- **Floating point.** Host arithmetic, with NaN results following the AArch64
  rules (signalling NaN first, then the first quiet NaN in operand order, else
  the positive default NaN), which differ from x86's.
- **Exclusives.** A load-exclusive records the address and value; a
  store-exclusive is a compare-and-swap against that value.

`module_host` (built only when `SWITCH_RECOMP_LIFTED` names a lift output
directory) loads the module's segments at their link addresses from an
**unrelocated** ELF (`nso.py --no-relocate`): the module's own startup applies
its relocations, and loading a pre-relocated image adds the base twice. It
starts the main thread with x0 = 0 and x1 = its thread handle, runs guest
threads on host threads (`ExitThread` unwinds to the thread's root), and
serves the memory, thread and information SVCs itself; IPC and
synchronization SVCs go to the kernel. A native `sm` (`src/services/sm.cpp`)
speaks TIPC on `sm:` and maps `RegisterService`/`GetServiceHandle` onto
kernel named ports, so a port the module registers is announced across links
like any other. Like the real `sm`, it holds a `GetServiceHandle` for a name
that is not registered yet and answers once it is.

The services the module calls are served by `NativeHost`
(`src/services/native.cpp`): authored CMIF interfaces in one kernel process,
with sub-interfaces returned as moved sessions or, once the client converts a
session to a domain (Nintendo's clients do), as domain object ids. The stubs
(`src/services/stubs.cpp`) answer only commands the module has been seen to
call, and report anything else:

| Service | Commands answered | Answer |
| :--- | :--- | :--- |
| `lm` | `OpenLogger`; `ILogger` `Log`, `SetDestination` | accepted and dropped |
| `pm:bm` | `GetBootMode`, `SetMaintenanceBoot` | boot mode from `RT_BOOT_MODE`, default 1 (maintenance); 0 (normal) since phase 2 |
| `fsp-srv` | `SetCurrentProcess`; system save create, open, read extra data, extend; `IFileSystem` create, delete, open, entry type, commit, space; `IFile` read, write, flush, size | an in-memory save store that starts empty, as on a fresh console |
| `ovln:snd` | `OpenSender`; `ISender` `Send` | accepted and dropped |
| `arp:r` | launch and control property queries (by PID or program ID), command 6 | the process given by `--application` is a running application with that program ID, version and `control.nacp`, on the SD card, instance ID 1; any other caller is "not registered". Command 6 is read as `GetApplicationInstanceId(pid)` (libnx's numbering; pctl sends a PID): an assumption |
| `set:sys` | `GetSettingsItemValue`, `GetSettingsItemValueSize` | a table of items; `pctl!ignore_post_event_interval_from_server` is `false` (an assumption: the retail default is not in the module) |
| `time:u` | user, network, local and ephemeral system clocks; steady clock; time zone (UTC: location name, calendar and POSIX conversion, its event); shared memory of clock contexts | the host's clock, as on a console whose clocks are set |
| `psc:m` | `GetPmModule`; `IPmModule` initialize, request, acknowledge, finalize | the power state never changes |
| `bsd:s` | register client (commands 0 and 33), `StartMonitoring` | every socket operation fails with `ENETDOWN` |
| `nifm:s` | `CreateGeneralService` | no command answered: queries fail, which pctl treats as offline |
| `ssl:s` | `SetInterfaceVersion` | contexts refused |
| `npns:s`, `bgtc:t` | everything (`bgtc:t` opens its interfaces with commands 100 and 101) | events that never fire, otherwise success with zeroed output |

The other client services in the NPDM (`fatal:u`, `acc:e:u1`, `bsdcfg`,
`dauth:0`, `nsd:u`, `pdm:qry`, `set`, `set:cal`, `sfdnsres`, `srepo:u`) are
registered as placeholders that answer every command with an error and log
it; start-up in either boot mode connects to some but needs none of them. A
module that reaches `fatal:u` has hit a failure, and the call before it is
the one to look at.

`RT_PROBE=1` adds a client (`src/services/probe.cpp`) that connects to `pctl`,
calls `CreateService` and then `IsRestrictionEnabled` on the returned
`IParentalControlService`, prints the replies and ends the host.

Bring-up notes, each confirmed against the module's own code:

- `QueryMemory` must report unmapped memory as `Free` (state 0); the startup
  code probes past the module's end for free space.
- `GetInfo` types 28 (alias region extra size) and the pair 37/38 (an extra
  region's address and size) are queried; 0 means "none".
- A TIPC reply must have the request's message type (16 + command) and
  exactly `1 + outputs` data words; the client checks the whole header
  (including the special header for a moved handle) and aborts otherwise.
- The kernel writes each thread's own handle at offset 0x110 of its
  thread-local region: the module's mutex code reads it there to recognise a
  lock it already holds, and nothing in user code writes it.
- `DT_INIT` and `DT_FINI` are called by offset from the module base, so the
  lifter takes them from the module's dynamic section as entry points.
- Thread stacks come from `MapMemory` (an alias of a `.bss` buffer in the
  stack region). The source is inaccessible while mapped, so the host copies
  in on map and back on unmap.
- The time service's shared memory holds the clock contexts every reader
  computes the time from. The kernel gives shared memory to a mapping process
  as a copy of its contents at that moment (`CreateSharedMemory`,
  `MapSharedMemory`); the contexts are offsets, so a snapshot stays correct
  as the guest's tick counter advances. Live sharing between processes is not
  implemented.
- Clients clone domain sessions (`CloneCurrentObject` on a domain): the clone
  is a new session with the same object table.
- `Break` from an abort passes a pointer to a result code; the host prints it.
- `RT_TRACE=1` logs every SVC. A lift with `--track-pc` stores the guest PC
  before each instruction, and the fault handler then prints it with registers
  and a frame-pointer backtrace.

### Kernel decisions so far

- **Language.** C++20 for the kernel, with a plain C entry (`include/hk/svc.h`)
  for generated code, so either C (WindowSmash-style) or C++ (Belmante-style)
  output can call it.
- **Result codes** use the kernel module (1) with Horizon's descriptions:
  `InvalidHandle` 114, `InvalidPointer` 115, `TimedOut` 117, `OutOfRange` 119,
  `NotFound` 121, `SessionClosed` 123, `InvalidState` 125, `OutOfSessions` 7,
  `MessageTooLarge` 260. These choices are this kernel's own:
  `NotImplemented` (33) for light sessions, receive lists in the message
  buffer itself (mode 1), A/B/W buffers in a reply, and unknown SVCs;
  `InvalidState` for registering a name twice; a reply that cannot be
  delivered ends the client's call with `SessionClosed`. Synchronization adds
  `InvalidAddress` 102, `InvalidCurrentMemory` 106 and `Cancelled` 118;
  buffers add `OutOfMemory` 104 and `ReceiveListBroken` 258.
- **Buffers are copied, not shared.** An X buffer's bytes go into the
  receiver's receive list (one packed buffer, or one per X index), read from
  the receiver's message buffer when the message arrives. A, B and W buffers
  are copied into a region the receiving process maps for the request
  (`GuestMemory::MapIpcBuffer`); when the server replies, B and W are copied
  back to the client's addresses and the region is unmapped. Across a link
  the bytes travel in the frames, and the reply carries B and W back. B is
  copied in as well, so bytes the server does not write come back unchanged.
  One message carries at most 64 MiB of buffers. A request abandoned without
  a reply (the session closes first) leaves its mapping until the server
  process ends.
- **Threads and synchronization.** The kernel owns thread objects (ids,
  handles, exit signalling) and events, and implements `WaitSynchronization`,
  `CancelSynchronization` and the address arbiter: `ArbitrateLock`/`Unlock`
  hand a guest mutex directly to the next waiter (the word holds the owner's
  handle, plus `0x40000000` while others wait), and the condition-variable
  SVCs release the mutex on wait and re-queue a signalled thread for it.
  Waiters are served first come, first served; priorities are not modelled.
  The runtime runs the threads; `GuestMemory::CompareExchange32` gives the
  kernel atomic access to guest words.
- **Locking.** One kernel mutex and one condition variable. Simple and correct
  for a handful of sessions; revisit if a hot service makes it a bottleneck.

## Verification

- **Shadow comparison.** With `NX_SYSMODULE_SHADOW=pctl`, each request goes to
  both the verified endpoint and the child. The verified reply is the one
  delivered to the game; the child's reply is compared byte for byte and any
  difference is logged with the command id. A clean comparison across MK8D's
  startup and a race is the first milestone.
- **Then substitution.** With `NX_SYSMODULE_PORTS=pctl`, the child's reply is
  delivered. The existing startup and race flights must reach the same reviewed
  frames.
- **Authored tests.** A small authored server (no firmware) registers a port,
  accepts sessions and echoes requests. It is C++ that reaches the kernel only
  through the `extern "C"` `hk_svc` register interface and its own guest
  memory, the same boundary recompiled code uses, so milestone 1 needs no
  AArch64 lifter. It exercises the kernel subset, the message copy and handle
  translation without any game or firmware input.
- **Lifter differential test.** `tools/difftest.py` lifts every distinct
  straight-line or conditional-branch instruction word in a module on its own,
  runs each from random register, flag, vector and memory states both as C++
  and in unicorn, and compares registers, flags, branch outcome and every
  changed byte. States are biased so loads and stores land in mapped scratch.
  For `pctl`: 47,456 distinct words, 347,493 cases, all exercised, no
  differences. Planting a carry-flag bug makes it fail, as it should.
- **Kernel synchronization tests.** `tests/sync_test.cpp` drives two guest
  threads through events, thread-exit signalling, cancellation, mutex hand-off
  and condition variables (8 cases; 100 of 100 repeated runs pass).
- **Buffer tests.** The echo server's `Buffers` command takes X, A, B and W
  buffers and answers through B, W and an X of its own; `ipc_test` checks the
  bytes in one host and that a too-large X fails with `ReceiveListBroken`,
  and `transport_test` checks the same exchange across the link.
- **Native service tests.** `tests/native_test.cpp` covers sub-interfaces as
  moved sessions, domains (convert, object ids, close) and `sm` deferral.
- **No default change.** All existing suites and GPU checks must pass with the
  switches unset, and the title executable's default path is unchanged.

## Findings: the `pctl` sysmodule (firmware 23.0.1)

Measured with `tools/nca.py`, `tools/nso.py` and the Ghidra scripts in
`tools/ghidra/` (Ghidra 12.1.4 headless). Function addresses assume the module
loaded at `0x7100000000`; "startup" means reachable from the start routine by
direct calls (through thunks), which shows a call is possible at startup, not
that every branch takes it.

**Module.** Program `010000000000002E`, build ID `737a4b3d264f5b19...`. One
NSO: text `0xf8124`, rodata `0x48788`, data `0x10e70`, bss `0x16c190` bytes,
5,447 relative relocations (RELA and RELR). C++ RTTI names are present, for
example `nn::pctl::detail::ipc::IParentalControlServiceFactory` and
`ParentalControlServiceFactoryImpl`.

**Main (`0x7100000110`).** In order:

1. Queries `pm:bm` (`0x710001f150`) for the boot mode.
2. Names its thread `nn.pctl.IpcServer` and builds a server manager.
3. Registers four ports with their session limits and capability masks:

   | Port | Sessions | Mask |
   | :--- | ---: | :--- |
   | `pctl` | 6 | `0x303` |
   | `pctl:s` | 8 | `0x838e` |
   | `pctl:a` | 1 | `0x83be` |
   | `pctl:r` | 1 | `0x8040` |

   mk8-recomp's verified service uses the same `0x303` for `pctl`
   (`NamedPctlCapabilities`) and `0` for the restricted ports. MK8D opens the
   restricted ports without calling methods, so that difference is not visible
   to it.
4. Runs `0x7100035a10` in every boot mode (it reaches `fsp-srv`).
5. Unless the boot mode is 1 (maintenance), runs the large initializer
   `0x71000364a0`: sockets (`bsd:s`, with a fixed socket configuration),
   `nifm:s`, `time:u`, `pdm:qry`, accounts (`acc:e:u1`), the TLS stack
   (`ssl:s`), then the parental-control core objects. It then registers with
   `psc:m` (power state, module id `0x2c`) and `bgtc:t` (background tasks),
   and adds both events to the server's wait list.
6. Serves forever: one loop waits on the IPC sessions, the power-state event
   and the background-task event, and dispatches each.
7. On exit, unregisters from `psc:m` and `bgtc:t` and tears down.

**Services by phase.**

| Phase | Services |
| :--- | :--- |
| Every boot | `pm:bm`, `fsp-srv` |
| Normal boot startup | `bsd:s`, `nifm:s`, `time:u`, `pdm:qry`, `acc:e:u1`, `ssl:s`, `set:sys`, `psc:m`, `bgtc:t`, `ovln:snd`, `lm` |
| On demand (from IPC handlers) | `set`, `set:cal`, `srepo:u`, `dauth:0`, `arp:r`, `sfdnsres` |
| No code references | `bsdcfg`, `npns:s`, `nsd:u`, `fatal:u` |

The no-reference group is declared in the NPDM but never named in code (or
named only through a path the scripts do not follow); none is needed to start.

**Consequence.** The maintenance-mode branch is the smallest path to a serving
`pctl`: answering `pm:bm` with boot mode 1 skips the networking, account, TLS,
power-state and background-task setup, leaving only `pm:bm` and the
`0x7100035a10` filesystem path before the module registers its ports and
serves. That is a reasonable target for milestone 2. It is not equivalent to a
normal boot: commands that depend on skipped subsystems may fail or differ, so
the shadow comparison must still run against a normal-boot configuration
before any substitution. For a normal boot the stub list is the 13
startup services above, most of which can answer as "no network" or "no
change".

## Open questions

1. **Which module hosts `pctl`. Resolved.** Firmware 23.0.1 has a dedicated
   `pctl` sysmodule, program `010000000000002E`, whose ExeFS is just `main` and
   `main.npdm`. Its NPDM service access control hosts exactly `pctl`,
   `pctl:a`, `pctl:r` and `pctl:s`: the four ports MK8D opens. By contrast
   `aoc:u` is hosted by `ns` (`010000000000001F`), which hosts 14 services and
   is a client of 46, so it is not a good second target.
2. **Dependencies of the module itself.** The `pctl` NPDM declares 23 client
   services: `acc:e:u1`, `arp:r`, `bgtc:t`, `bsd:s`, `bsdcfg`, `dauth:0`,
   `fatal:u`, `fsp-srv`, `lm`, `nifm:s`, `npns:s`, `nsd:u`, `ovln:snd`,
   `pdm:qry`, `pm:bm`, `psc:m`, `set`, `set:cal`, `set:sys`, `sfdnsres`,
   `srepo:u`, `ssl:s` and `time:u`. These are permissions, not proof of use:
   static analysis now splits them by phase (see Findings); the first run
   confirms which calls are actually made. Each is
   either forwarded back to the title's HLE or stubbed for the experiment,
   and every stub is listed in the results. Networking (`bsd:s`, `nifm:s`,
   `ssl:s`, `npns:s`) is expected to be the largest group and should be
   answered as "no network" rather than implemented.
3. **Code discovery for sysmodules. Answered for `pctl`.** The lifter's own
   discovery (see Lifter and module host) covers the module: every jump table
   is recognised and the remaining indirect branches are function-pointer
   tail calls. Gaps halt explicitly, never fall through silently.
4. **Cost.** A cross-process round trip per request is acceptable for `pctl`,
   which MK8D calls a handful of times. It would not be acceptable for a hot
   service; measuring it on the first target tells us whether `fs` needs the
   in-process address-space design instead.

## Milestones

1. Authored echo server passes through the server-side kernel subset and
   transport (no firmware).
   - **Done: kernel and message copy, in one host process.** `src/kernel/`
     implements handle tables, named ports, sessions and `CloseHandle`,
     `ConnectToNamedPort`, `SendSyncRequest`, `CreateSession`,
     `AcceptSession`, `ReplyAndReceive` and `ManageNamedPort`, with HIPC copy
     between processes that have separate guest address spaces: copied and
     moved handles are translated, the PID is written by the kernel, and a
     failed copy changes neither process. `tests/ipc_test.cpp` runs 11 cases
     (round trip, kernel PID, sub-interface returned by moved handle, moved
     server session, copied handle, rejected buffer descriptors, close in each
     direction, session limit, bad arguments, address-space isolation). They
     pass under MSVC (Debug and Release, 300 repeated runs) and GCC 13.
   - **Done: the cross-process link.** `echo_host` runs the same echo server
     in its own host process with its own kernel; `tests/transport_test.cpp`
     drives it over a pipe link through 10 cases: round trip (1,000 calls),
     PID, sub-interface and server session moved across the link, copied
     handle, buffers rejected before sending, client close, server quit,
     host crash (sessions close, the port disappears) and the session limit.
     Both suites pass under MSVC and GCC 13 with no warnings; repeated Release
     runs passed 300 of 300 (in-process) and 100 of 100 (cross-process).
   - Windows only so far: `src/kernel/platform_win32.cpp` holds the pipes and
     the cancellable I/O threads. Frames use host byte order.
2. The recompiled `pctl` host completes its own startup in a child process and
   registers its ports, first on the maintenance-mode path (`pm:bm` and
   filesystem only), then on the normal path.
   - **Done: lifter and module host.** The whole module lifts and builds (MSVC,
     about 40 s); every instruction form it uses passes the differential test.
     `module_host` runs it through the C runtime's startup (memory queries,
     `GetInfo`, heap and TLS set-up, thread queries, guest mutexes) to its
     first service calls: it connects to `sm:`, registers as a client, and
     asks for `lm`.
   - **Done: maintenance-mode start-up and serving.** With buffers in the
     kernel and the stubs above, `pctl` reads boot mode 1, registers `pctl`
     (6 sessions), `pctl:s` (8), `pctl:a` (1) and `pctl:r` (1), creates and
     writes its system save `8000000000000100`, sends overlay notifications,
     starts its worker thread and waits in its server loop. `RT_PROBE=1`
     gets a moved `IParentalControlService` from `CreateService`; its
     `IsRestrictionEnabled` (1031) answers success and `false`. (An earlier
     probe sent command 1403 by mistake and got `0x10A8E`.)
   - **Done: normal start-up and serving.** With `RT_BOOT_MODE=0` pctl also
     sets up sockets (registration only), the network manager, the clocks
     and time zone, SSL, push notifications, power state and background
     tasks, reads one system setting, cleans and rewrites its save, then
     serves; the same probe passes. Left running for 90 seconds it polls
     `nifm` about once every ten seconds and does nothing else.
   - **Milestone 2 is complete.** Known gaps, none of which start-up needs:
     `arp:r` command 6; the placeholder services; shared memory is a
     snapshot; guest memory permissions are not enforced; a request abandoned
     without a reply keeps its buffer mapping until the server exits.
   - **Next (milestone 3):** run `module_host` as a child process linked to
     MK8D, with the title's `sm` and a forwarding bridge, and shadow-compare
     its replies with the verified `pctl`.
3. Shadow comparison clean across MK8D startup and one race. (Closed on
   start-up and a second title instead of a race; see the end of this item.)
   - **Done: the client side and a game-free shadow check.** `module_host
     --link` and `--application`, the `module_client` library and
     `client_test` (requests, PID, sub-interfaces, a missing port and a child
     crash, against an authored CMIF host in its own process). Native
     services now end every reply with the rest of the 16 bytes reserved for
     header alignment, as the system's own servers do; clients that trimmed
     it found nothing to trim before.
   - **Done: shadow check without the game.** `pctl_shadow` starts the
     recompiled `pctl` with Mario Kart 8 Deluxe (`0100152000022000`, update
     4.0.1, its own `control.nacp`) registered as the application and makes
     the calls the verified service implements. On port `pctl` all nine
     agree in both boot modes: `CreateServiceWithoutInitialize` and
     `CreateService` return a service; `Initialize` succeeds;
     `IsRestrictionEnabled` is `false`, `GetStereoVisionRestriction` `false`
     and `IsStereoVisionPermitted` `true`. On `pctl:s`, `pctl:a` and `pctl:r`
     the two differ, as known: the verified service gives those ports no
     capabilities and refuses `Initialize` and `CreateService` with
     `0x1068E`, while firmware gives them capabilities and the module
     succeeds. MK8D never calls methods on those ports.
   - **Done: the title side, and a clean shadow of MK8D start-up.**
     mk8-recomp's runtime recipe gains `runtime/src/mk8_sysmodule_link.*`,
     built when configured with `NX_SWITCH_RECOMP_DIR`: it starts
     `module_host` through `module_client`, and either shadows the verified
     pctl bridge (`NX_SYSMODULE_SHADOW`: each request also goes to the module,
     the verified reply is delivered, every comparison is logged, and
     sub-interfaces are shadowed by the module's own) or forwards to the
     module (`NX_SYSMODULE_PORTS`). Built against MK8D 4.0.1 (the base
     program is AArch32; the update's AArch64 program is the one that runs),
     the runtime's 57 tests pass. In the game's own start-up it opens all four
     ports and makes five calls (`CreateServiceWithoutInitialize` on each
     port, then `Initialize` on the `pctl` child): all five agree. With the
     module answering instead, start-up takes the same path. Both runs, and
     a run without the module, then stop at the same null access after
     `content:/` lookups fail: no RomFS was supplied, which this comparison
     does not need, since pctl comes before the GPU device and any asset.
   - **Done: the game's local inputs, except shaders.** `nca.py --romfs`
     applies the update's patch section to the base RomFS: its indirect table
     (3,648 relocations) maps each range to the base or the patch, and patch
     data is decrypted with AES-CTR-Ex (1,106 subsections, each with its own
     counter generation). All 740,490 blocks of the 12.1 GB image match their
     IVFC hashes. `nca.py --system-data` writes the firmware's font and Mii
     archives the same way, and mk8-recomp's `font_bundle.py` packs the seven
     decrypted fonts. With these, MK8D runs 120 seconds at 60 fps with audio
     and no fault, and the shadow stays clean, but every draw is skipped
     (`NX_SKIP_MISSING_SHADERS`): no shader is translated yet.
   - **Shaders, for local testing:** the upstream runtime's Ryujinx-based
     `spirv_harness` translates the shaders the runtime dumps as it meets
     them (MK8D's raw compute blocks wrapped in the header it expects, and
     fragment shaders that write integer targets given unsigned outputs).
     After a few play-and-translate passes (about 2,500 stages) the title
     screen renders, and the shadow is still clean. This is not the
     suyu-based cache mk8-recomp uses, so rendering is not verified.
   - **Done: a second title, Super Smash Bros. Ultimate (WindowSmash).**
     WindowSmash had replaced the SDK's two `nn::pctl` checks with native
     functions; without them, the SDK's own client runs and its requests reach
     `ipc_sysmodule.c`, which either answers permissively or forwards them
     through `hk_module_client.dll` (the C interface) to `module_host`. SSBU
     asks nothing at start-up; entering Online it opens all four ports
     (`CreateServiceWithoutInitialize` on each), then sends `Initialize` and
     `CheckFreeCommunicationPermission` (1001). The module answers all six
     with success, and the game joins the online lobby as it does with the
     native answers. There is no verified service on this side to shadow
     against, so this is forwarding only.
   - **Milestone 3 is complete, without the race.** The verified service
     serves five commands on the service object (1, 1031, 1062, 1065 and
     1432) and stops the game on any other, and mk8-recomp's runs reached
     races with it, so a race could only compare commands from that set.
     The first four agree, in `pctl_shadow` and (for `Initialize`) in the
     game's start-up, and SSBU showed the module serving a second title's
     SDK, including a command MK8D never sends. The fifth, 1432, returns an
     event as a copied handle, which the link does not carry (the client
     closes copied handles), so it moves to milestone 5.
4. Substitution reaches the same reviewed frames as the default path. (Moved
   to the [plan](../plan.md)'s test harness.)
5. Measure round-trip cost, then decide between `aoc:u` (events) and `fs`
   (buffers) as the next target. Events include pctl's 1432 left over from
   milestone 3: carrying copied handles over the link, so that the title
   receives the module's event and can wait on it.
   - **Done: events across the link.** A readable event copied or moved
     across the link becomes a mirror in the other kernel: the owner sends
     every change of its signal state, a mirror's clears go back to the
     owner, and a generation count lets a signal that overtakes a clear
     stand. `Kernel::WatchEvent` tells host code about changes (for a title
     passing them to its own kernel's event), and `module_client` returns
     events as `client::Event` (C: `hk_module_event`). `transport_test` and
     `client_c_test` cover signal, clear in both directions, waiting and
     watching; 200 repeated runs passed.
   - **Done: 1432 in the shadow, and a real difference.** In firmware
     23.0.1 the method behind `GetSynchronizationEvent` (`0x710002ed50`)
     first requires capability `0x8`, which sessions on the application port
     `pctl` do not have (they carry `0x303`, enough for 1031, 1062 and
     1065), and returns `0x10A8E`; with the capability it then requires an
     object the module creates only during normal start-up, and returns
     `0x10E8E` in maintenance mode. mk8-recomp's verified service checks
     neither and returns an event. The shadow now includes 1432 on both pctl
     children and reports the difference; which reply the game should get is
     a question for mk8-recomp's verified service, not for the link. On
     `pctl:s`, whose sessions have the capability, the normal-boot module
     answers 1432 with its event, and the client receives it across the link
     as an unsignalled mirror: the end-to-end case with real firmware.
   - **Done: round-trip cost** (`roundtrip_bench`, Release, Windows, idle
     machine). A request to the echo server in the same kernel takes a 2 µs
     median (p99 12 to 16 µs); across the link 35 µs (p99 80 µs); a real
     recompiled `pctl` command (1031) across the link 43.5 µs (p99 96 to
     110 µs). That is fine for `pctl` and other services a game calls at
     start-up or in menus, and too slow for anything called many times per
     frame: a hundred such calls would take a quarter of a 60 Hz frame. So
     the services a game calls per frame (`nvdrv`, `hid`, `audio`, `vi`,
     `fs` during loads) run in the host process, native or as recompiled
     modules in the in-process mode, as the plan already has it. The next
     sysmodule target is chosen in the plan's phase 2.
