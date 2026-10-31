# System processes

Status: 2026-10-30. The start of the [plan](../plan.md)'s phase 2: the
recompiled sysmodules MK8D's next service needs, each in a host process of
its own beside the title.

## Why these modules

MK8D waits for `acc:u0` after its first GPU submission. In firmware 23.0.1
that port is not `account`'s: `ns` hosts `acc:u0` and `acc:su` (with `aoc:u`
and the `ns:*` ports) and reaches `account` through `acc:e`. Both need
`settings` (`set:sys`), whose defaults are compiled into it, so it is
recompiled too rather than stubbed item by item. `ns` checks a title's
rights with `es` (`ndrm:lu`) when the title initializes its account
service, so `es` followed.

| Program | Module | Functions | Hosts |
|---|---|---|---|
| `0100000000000009` | `settings` | 1,808 | `set`, `set:cal`, `set:fd`, `set:sys` |
| `010000000000001E` | `account` | 5,416 | `acc:aa`, `acc:e`, `acc:e:su`, `acc:e:u1`, `acc:e:u2`, `dauth:0` |
| `010000000000001F` | `ns` | 13,622 | `acc:su`, `acc:u0`, `acc:u1`, `aoc:u`, `ns:*` |
| `0100000000000033` | `es` | 2,641 | `es`, `ndrm:la`, `ndrm:lu` |

## Running them

```
python tools/nca.py --keys <prod.keys> --firmware <firmware> --host acc --extract extracted
python tools/nso.py extracted/<id>-<name>/main extracted/<id>-<name>/<name>.elf
python tools/nso.py --no-relocate extracted/<id>-<name>/main extracted/<id>-<name>/<name>.load.elf
python tools/lift.py extracted/<id>-<name>/<name>.elf out/lifted/<name>
python tools/nca.py --keys <prod.keys> --firmware <firmware> --system-data out/system-data all
python tools/calibration.py out/calibration.bin
python tools/nca.py --keys <prod.keys> --firmware <firmware> --content-index out/content <game.xci> <update.nsp> <dlc.nsp>

module_host --system-data out/system-data --calibration out/calibration.bin --content out/content
            --sysmodule out/clang-settings/module_host.exe extracted/.../settings.load.elf
            --sysmodule out/clang-account/module_host.exe extracted/.../account.load.elf
            --sysmodule out/clang-es/module_host.exe extracted/.../es.load.elf
            --sysmodule out/clang-ns/module_host.exe extracted/.../ns.load.elf
            --application 0x50 0100152000022000 0x170000 <control.nacp>
            --title out/mk8d-layout --romfs <romfs image>
```

`--application` registers MK8D with `arp:r` in every host, as `ns` and `am`
do on the console when it launches; `account` and `ns` look it up there.

Each `--sysmodule` starts a `module_host` built with that module's lift as a
linked child (`hk::platform::LinkedProcess`, which `module_client` uses too).
The parent passes on what the children need:

- **Process ids** from `0x20`, below the application's, as on the console.
  The root host serves `pm:info` (GetProgramId) for every process, `pgl`,
  and `ncm` and `lr`; the children leave theirs out and reach the root's.
  Its native services run in three hosts (stubs, the application's
  services, content), each a server thread of its own: a thread waits on at
  most 0x40 handles, as on the console, and one was not enough for MK8D and
  three sysmodules.
- **Which stubs to leave out** (`--omit`): every service any of the modules'
  `main.npdm` hosts (the service access control's server entries), so that
  `account`'s `dauth:0` or `ns`'s `aoc:u` comes from the module, not a stub.
- **`--system-data` and `--calibration`**, and **`--log-prefix`**, which
  starts every line a child writes with its module's name.

## The kernel relays between links

A child reaches a port registered in another child through the parent's
kernel, which joins the two links:

- A port registration from one link is passed on to the others, and
  withdrawn once nothing reaches it.
- A connect for a port that is not local goes on to the link that has it;
  the session that comes back is held for the asking link.
- A request on such a session is passed on: what it carries is imported from
  one link and exported to the other, so moved sessions, copied events and
  process handles cross two links as they cross one. Replies come back the
  same way, writebacks included. A server end does not pass through a relay.
- A closed server, a broken link and an event's clears reach the far side.

- A session sent back over the link it is served across, as `ns` returns
  an object it got from `account` to the title, crosses as the peer's own
  client end (`PeerClientEnd`, named by the peer's id): the peer hands out
  the session it holds. A moved one passes its reference over; no close is
  sent.

`transport_test` runs all of its cases a second time with the echo host two
links away, through a kernel in the middle, and sends a sub-interface back
to the host that serves it, copied and moved.

## Cores

`account` starts a thread that uses an object its main thread sets up after
a few requests to other services. On the console every sysmodule runs on
core 3, so a request hands the core to the server and back, and a thread of
lower priority in the client gets no time in between. The host now schedules
the console's four cores:

- The threads on a core run guest code one at a time, the highest priority
  first, and a thread gives up its core for every supervisor call; a thread
  of higher priority that became ready meanwhile goes first. Threads on
  different cores run in parallel.
- A thread waiting for a reply keeps its priority on its core for up to 2 ms,
  which stands for the server running on the same core. Without it,
  `account`'s thread ran ahead and called through a null pointer.
- Thread priorities and cores come from `CreateThread` and the NPDM (main
  thread priority at `0x0E`, default core at `0x0F`), and
  `Get`/`SetThreadPriority` and `Get`/`SetThreadCoreMask` report and change
  them.

MK8D still reaches its first GPU submission under it.

## Fibers

`ns` runs its tasks on contexts of its own (fibers), and MK8D's SDK and
`account` carry the same switch: save the callee-saved registers, store sp
through `x0`, load the other context's sp through `x1`, restore its
registers from its stack and `ret` into it. Lifted code returns through the
host stack, so `tools/lift.py` recognises that `mov sp, xN` (sp loaded from
memory, not the frame, with `x30` then restored from the new stack, which
`longjmp` and a restored frame pointer do not do) and calls
`rt::SwitchStack`:

- Every suspended context is a host fiber, kept under the guest sp it left;
  a switch resumes the fiber kept under the target sp.
- A target never seen before is a new context: a new fiber runs the
  instruction after the switch (made an entry point), which restores the
  registers its creator laid out, then its function at `x30`.
- `ns` resumes contexts on other threads than the one that left them, so
  each context has CPU state of its own, and a switch copies the switching
  thread's state into it, as the registers carry across on the console.

## What the modules needed

From the host's stubs, in the order they asked:

| Service | What | Note |
|---|---|---|
| `fsp-srv` 202 | OpenDataStorageByDataId | system data archives from `--system-data`: `settings` reads `0818` (Icosa platform config) and `081F` |
| `fsp-srv` 12 | OpenBisStorage(27) | the calibration image; `set:sys` GetSerialNumber reads it, and a blank image passes as long as each block's CRC16 is right (below) |
| `fsp-srv` 67 | FindSaveDataWithFilter | over the in-memory system saves; `account` looks before it creates |
| `spl:` | GetConfig 5, 6, 8, 14; IsDevelopment | a retail Icosa; device id fixed (`HOST01`) |
| `time:u` | shared memory | firmware 23 reads the steady clock's continuous adjustment at `0xD0`, which needs the clock source id |
| `nifm` | EnumerateNetworkInterfaces, CreateRequest | one wireless interface with a fixed, locally administered MAC; requests never granted |
| `npns:s` 120 | CreateNotificationReceiver | a receiver whose command 4 gives an event; `account` listens for `account.membership` |
| `set:sys` 62, 183 | GetDebugModeFlag, GetPlatformRegion | for modules run without the recompiled `settings` (`pctl`'s shadow) |
| `srepo:u` | reports | accepted; 13005 gives the report buffer, 16 KB of shared memory with its size, offset and length |
| `pgl` (TIPC) | GetShellEventObserver (20) | an observer whose event never signals: the host starts no process after boot |
| `time:su` | the same IStaticService as `time:u` | |
| `nim`, `pdm:ntfy` | network installs, play events | accepted, none |
| `fsp-srv` 21, 22, 25, 57, 59, 61 | delete, create (an application's save by its attribute), extra data | over the in-memory saves |
| `fs` IFileSystem 5, 6 | RenameFile, RenameDirectory | in the in-memory saves |
| `arp:r` 3, 0 | the application's instance id and launch property | newer firmware names the application by instance id (1) where older took its process id |
| `time` 202 | ToPosixTimeWithMyRule | UTC; `pctl` asks it for the next month's start, so it was first needed on 30 October |
| `pm:bm` | GetBootMode | now normal (0) by default: `ns` registers `aoc:u` only in a normal boot |
| `spl:es` | GetConfig, IsDevelopment, GenerateAesKek (2), ImportEsKey (17) | the key commands are opaque (below) |
| `fsp-srv` 37 | CreateSaveDataFileSystemWithCreationInfo2 | a system save, from the attribute at 8 and the sizes at 0x48 of its creation info; `es` makes its five (`80000000000000E0` to `E4`) this way |
| `fs` IFileSystem 9 | OpenDirectory | an IDirectory over the in-memory save: the entries under it when opened |
| `fsp-srv` 400, 500 to 503, 510, 620, 630, 631 | a device operator, detection notifiers, SD card seed and accessibility | no SD card, no game card; the notifiers' events never fire |
| `caps:c`, `hid:sys`, `bcat:u`, `bcat:s` | the album, system input, background delivery | quiet; `hid:sys` 713 gives an event; a `bcat` service's sync and suspension requests are done at once (their event signalled, status 9) |
| `csrng` | GenerateRandomBytes | the host's random source |
| `npns:s` 40 | an event | |
| `arp:r` 4, 5 | the unregistration notifier, ListApplicationInstanceId | |
| `pgl` 5 to 10 | GetApplicationProcessId, BoostSystemMemoryResourceLimit, crash report and tracking | for `ns`'s launch; nothing is tracked |
| placeholders | `spl:mig`, `ectx:w`, `caps:dc`, `avm` | opened only, so far |

`RT_TRACE` now also names each command a recompiled server receives (with
its first four argument words) and the result it replies with, which is how
requests across links are followed. Each svc line names its thread (its TLS
address); a WaitSynchronization lists its handles, with a backtrace when it
has no timeout; a SendSyncRequest lists the handles the reply carried.

`pgl` speaks TIPC, as `sm` does: the command is the message type less 16,
the arguments are the data words with no header, and the reply keeps the
type and starts with the result. `NativeHost` now serves it alongside CMIF
on any port, with sub-interfaces returned as moved sessions that speak TIPC
too (`native_test`'s TipcRequestsAreServed). `ns` sent its `pgl` request as
TIPC to the CMIF placeholder before, and stopped on the reply's header.

## es

`es` keeps tickets and the rights of running titles (`ndrm:*`). At
start-up it:

- creates and opens its five system saves (`fsp-srv` 37 and 52) and reads
  their directories;
- reads its device certificate and eticket key from `set:cal`. `settings`
  checks each calibration block's CRC16 (Nintendo's: the reflected 0xA001
  polynomial from 0x55AA) before it answers, so `tools/calibration.py` now
  writes the CRC at the end of each of the 52 blocks `settings` checks;
- hands the eticket key to `spl:es` (GenerateAesKek, then ImportEsKey).

The host has no console keys, and the eticket key in a blank image is zero,
so `spl:es` cannot do what the security processor does. Nothing needs it
to: the host's `fs` reads content with the host's own keys and never through
`es`. Its key commands are therefore opaque: an access key is a handle only
`spl` reads back, and the eticket key is accepted and kept by no one (the
host has no personalized tickets).

`es` then registers `es`, `ndrm:lu` and `ndrm:la` and serves.

## Content: ncm and lr

`ncm` (content storages and content meta databases) and `lr` (location
resolution) are native, over an index `tools/nca.py --content-index` writes
from the firmware's and the user's own packages
(`src/services/content.cpp`):

- `<folder>/<storage>/<id>_<version>_<type>_<install type>.meta`: each content
  meta in the form `ncm` keeps it (a header, the extended header, the
  contents with the meta NCA itself first, as `ncm`'s installer records it,
  and the content metas it lists). The firmware's 121 are BuiltInSystem's;
  the packages are installed in BuiltInUser, keeping only the newest version
  of each (MK8D: the game, the 4.0.1 update, the DLC).
- `<folder>/<storage>/contents.txt`: where each content's NCA is (content
  id, offset, size, its rights id and key generation, file), for when `fs`
  serves contents; the content storages answer GetRightsIdFromContentId
  from it. MK8D's cartridge contents have no rights id; the update's and
  the DLC's do.
- The meta databases answer the queries `ns` makes (List, Get,
  GetLatestContentMetaKey, GetAttributes, ListContentInfo and the rest);
  the content storages are read only, with no placeholders. The game card
  and SD card are empty storages.
- `lr` resolves a program, control, data or document path from a storage's
  newest content meta (a patch's program over the application's), with
  redirections first; paths name the content (`@UserContent://registered/
  <id>.nca`), which `fs` does not open yet.

## Where it stands

- `settings`, `account`, `es` and `ns` all finish start-up and serve: `ns`
  registers `aoc:u`, `acc:su`, `acc:u1` and `acc:u0` with its `ns:*` ports.
- MK8D gets `aoc:u` and `acc:u0` from `ns`, and its `acc:u0`
  InitializeApplicationInfo (100) reaches `ns`, which checks the title's
  rights with `ndrm:lu` 1000 (one u64 in, the application's instance id 1;
  one u64 out). `es` answers `0x14FA` (module 250, description 10) from its
  own state, touching no other service: it has no record of the
  application, and `ns` aborts.
- That record is made at launch: `ns` uses `ndrm:la` (and `arp:w`) itself,
  in the path that launches an application. The host starts MK8D directly
  and stands in for that path only with `--application` (`arp:r`), so `ns`
  never told `es`.
- `pctl`'s shadow is as before in both boot modes: 12 the same, 8 different.

## Launching through ns

On the console `am` launches an application, and `am` uses neither `pgl`
nor `pm`: it asks `ns` (through `ns:am2`), and `ns` acquires the rights,
registers the instance with `arp` and calls `pgl` LaunchProgram.
`module_host --launch` (with `--title`) holds the title's main thread until
`pgl` LaunchProgram names its program, and a launcher thread in the root
(`services::StartLaunch`, `src/services/probe.cpp`) does `am`'s part:

1. `ns:am2` GetApplicationManagerInterface (7996).
2. PushApplicationRecord (16) for every application installed in the
   content index (event 3, installed; content storage records for the
   application, its patch and its DLC), as an installer does. `ns` keeps
   its records in a save the host does not keep, so they are pushed at every
   start.
3. GetApplicationLaunchInfo (95): the 0x80-byte launch info (application id,
   program id, version at 0x10, storages at 0x1C).
4. CreateApplicationInstance (2517): `ns` registers the instance with
   `arp:w` (a launch property, then Issue) and returns its id, which the
   launch info carries at 0x30.
5. The launch: 2513 (or LaunchApplication, 94, with a program index byte
   first), then AcquireApplicationLaunchInfo (96).

`ns:dev` no longer has LaunchApplicationForDevelop (8) in this firmware; an
unknown command closes the session, as the console's server does.

`arp` is native in the root now, serving every process: `arp:w`'s registrar
issues instance id 1, which `arp:r` reports. What it registers is logged,
not yet read back (`arp:r` still answers from `--application`).

Where it stops: step 5 returns `0xE10` (ns 7). `ns`'s launch routine looks
the instance up in its table of rights environments (16 entries, keyed by
instance id, each holding an `ndrm:la` handle), and nothing has made that
entry. `ns` makes it in a helper that does the whole launch (create the
instance, create its rights environment, get the program index, launch,
keep the launch info); that helper is slot 0 of an internal interface `ns`'s
core implements, and which command `am` reaches it through is not found
yet. The candidates read so far:

- 2510 CreateApplicationResource returns an object whose command 0 checks
  `pgl` IsApplicationTracking and returns `0x1010` (ns 8);
- 65 returns an object made in another path to the same table insert.

Next: find the command that reaches the helper (or that makes the rights
environment for an instance), then follow MK8D through `es`'s tickets: the
update's and DLC's contents carry rights ids, so `es` will want their
tickets, which an installer imports from the packages.
