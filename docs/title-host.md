# The title host

Status: 2026-10-30. Milestone 4 of the [plan](../plan.md)'s phase 1: a whole
lifted title, Mario Kart 8 Deluxe 4.0.1, started on the host kernel and `sm`
with only the services it asks for, up to its first GPU submission.

## Running a title

`module_host --title <folder> --romfs <image>` takes the folder
`tools/nso.py --exefs` writes (`layout.txt`, each module's unrelocated
`<name>.load.elf`, `main.npdm`) and loads every module at its place in the
layout, `rtld` first. From `main.npdm` it takes the program id, the main
thread's stack size (1 MB for MK8D) and the address space, which must be the
39-bit one. The process is then an application:

- `SetHeapSize` maps and unmaps the heap region in 2 MB steps, and regions of
  the same kind next to each other merge, as `QueryMemory` reports them.
- `GetInfo` gives the program id, the 4 GB console's application pool as the
  total memory (`0xCD500000`), and says the process is an application.
- The main thread starts at `rtld` with the thread's own handle in `x1`;
  `rtld` relocates every module, links them through their GOTs and calls
  `main`'s entry, as on the console.

## What the lifter needed

Running a whole title found four things the lifter had not met in `pctl`:

- **Jump tables of 32-bit offsets** (`ldrsw` from the table, `add` the table's
  own address, `br`), about 1,500 of them across the four modules. Their base
  is often built well before the branch, through a register move, or the
  table is reached from a bounds check elsewhere; in that case entries are
  read while they stay near the branch. 13 remain unrecognised.
- **Lazily bound GOT slots** start out holding the PLT's resolver stub as an
  offset, not an address, so each module's PLT stub is now an entry point.
- **`rtld`'s position-independent idiom**, `bl` over a 32-bit word, which
  takes the word's address in `x30` and does not return there. It lifts as a
  branch that sets `x30`, and the words it names are entry points.
- **`adrp` and its `add` scheduled apart**: function pointers built that way
  are entry points too (411 more functions).

MK8D now lifts to 95,393 functions and 4.78 million instructions. difftest
tests every distinct instruction word in a module's text, reachable or not,
so the newly reachable code is covered by running it on all four modules:
every word now matches unicorn (the integer words of `main` and `subsdk0`,
410,273 of them, were the last to run). Jump table and entry point recovery
are not something difftest checks; a wrong table shows at run time as
`rt::BadJump` or a call to an address that is not an entry point. The
generated files are cut by address (128 KB of guest code each) and declare
only what they call, so a lifter change rebuilds only the files it touched:
19 s instead of two and a half minutes.

## Services MK8D touches

In the order the title first asks for them. Everything here is a hand-written
stand-in in the host process (plan.md, phase 2, replaces them), except
`nvdrv` and `vi`, which are native by design and here have no GPU or window
behind them yet.

| Port | Commands (interface: command ids) |
|---|---|
| `sm:` | RegisterClient, GetServiceHandle, over CMIF: the title's SDK predates TIPC |
| `lm` | 0 OpenLogger |
| `apm` | opened only |
| `appletOE` | 0 OpenApplicationProxy; IApplicationProxy 0, 1, 2, 3, 4, 11, 20, 1000; ICommonStateGetter 0, 1, 9; ISelfController 13, 16, 40; IWindowController 1, 10 |
| `aoc:u` | opened only |
| `pctl`, `pctl:s`, `pctl:a`, `pctl:r` | 1 CreateServiceWithoutInitialize; IParentalControlService 1 |
| `fsp-srv` | 1 SetCurrentProcess, 1005 GetGlobalAccessLogMode, 200 OpenDataStorageByCurrentProcess; RomFS reads |
| `nvdrv` | 3 Initialize, 8 SetAruid, 13 SetGraphicsFirmwareMemoryMarginEnabled, 0 Open, 1 Ioctl, 11 Ioctl2, 4 QueryEvent |
| `vi:m`, `vi:s`, `vi:u` | `vi:m` 2 GetDisplayService; IApplicationDisplayService 100, 101, 102, 1010, 2020, 2101, 5202; IHOSBinderDriver 1, 2, 3 |
| `hid` | 0 CreateAppletResource, 11, 100, 102, 103, 120; IAppletResource 0 |
| `time:u` | 0, 1, 2, 3, 300; ISystemClock 0, 2; ITimeZoneService 101 |
| `acc:u0` | asked for next: not served yet |

`nvdrv` opens `/dev/nvmap`, `/dev/nvhost-as-gpu`, `/dev/nvhost-ctrl-gpu` and
`/dev/nvhost-gpu`, and uses 22 distinct ioctls: nvmap Create, Alloc, GetId;
address space BindChannel, AllocSpace, MapBufferEx, GetVaRegions, AllocAsEx;
GPU control ZcullGetCtxSize, ZcullGetInfo, GetCharacteristics, GetTpcMasks,
GetActiveSlotMask; channel SetNvmapFd, SetTimeout, SetPriority, SetUserData,
AllocObjCtx, ZcullBind, SetErrorNotifier, AllocGpfifoEx2, SubmitGpfifo
(through Ioctl2). Through `vi`'s binder it calls IGraphicBufferProducer
RequestBuffer, DequeueBuffer, Query, Connect and SetPreallocatedBuffer.

## The first submission

```
nvdrv: GPU submission 1: 2 entries on syncpoint 20
  entry 0: 2186 words at GPU 0300160000 (title 011348b000): 20010000 0000b197 20012000 0000b1c0 20018000 0000b0b5 20014000 0000a140
```

That is NVN setting up its channel: it binds the Maxwell 3D (`B197`),
compute (`B1C0`), DMA copy (`B0B5`) and inline-to-memory (`A140`) classes to
subchannels. A second submission follows; the title then goes on to `hid`
and `time` and waits for `acc:u0`, the next service to write.

## Changes to the kernel and services on the way

- `sm` answers CMIF as well as TIPC, as the console's does for titles built
  with older SDKs.
- The current-process pseudo-handle can be copied (`am` receives it); a
  process crosses a link as its id.
- Transfer memory (`svc 0x15`): a range of its creator's memory that a
  native service resolves with `Kernel::FindTransferMemory` and works on in
  place (`nvdrv` reads command lists through it).
- Native services can answer into a client's C buffers (auto-select output
  sent as pointers), returned as X buffers in the reply.
- `vi`'s parcels list their binder objects, which Nintendo's `Parcel` checks
  before it reads one.
