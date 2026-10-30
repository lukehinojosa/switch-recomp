// module_host: runs a lifted sysmodule, or a lifted title, against the host
// kernel.
//
// Usage: module_host [options] <module.elf> [main-thread-stack-size]
//        module_host [options] --title <folder>
//
// Options:
//   --link <read> <write>   serve over a link to the parent host process, on
//                           two inherited pipe handles; the ports the module
//                           registers become reachable from the parent
//   --application <pid> <program id> <version> <control.nacp>
//                           the application arp:r reports for that process
//   --title <folder>        run an application: every module tools/nso.py
//                           --exefs laid out in the folder (layout.txt and the
//                           <name>.load.elf files), with the program id, main
//                           thread and address space from its main.npdm
//   --romfs <image>         the title's RomFS image (tools/nca.py --romfs),
//                           served by fsp-srv as its data storage
//
// The ELF is the module as tools/nso.py --no-relocate writes it: the same
// image the lift came from, but with relocations left for the module's own
// startup code to apply. Segments load at their link addresses. Set
// RT_TRACE=1 to log every supervisor call, RT_BOOT_MODE to choose what pm:bm
// reports (default 1, maintenance), and RT_PROBE=1 to check that the module
// serves pctl and exit (see services/probe.h).
#include "guest_space.h"
#include "hk/kernel.h"
#include "hk/link.h"
#include "rt/ops.h"
#include "services/application.h"
#include "services/probe.h"
#include "services/sm.h"
#include "services/stubs.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef CreateProcess

namespace rt {

namespace {

// Thrown by ExitThread to unwind a guest thread back to its host thread root.
struct ThreadExit {};

struct ThreadContext {
    hk_thread* kernel_thread{};
    uint64_t entry{}, argument{}, stack_top{}, tls{};
    std::thread host_thread;
};

// What GetInfo and the main thread need to know about the process.
struct ProcessInfo {
    uint64_t program_id = 0x010000000000002E; // pctl, the first module run
    bool application = false;
    uint64_t main_stack_size = 0x10000;
    uint64_t total_memory = 0x10000000;
};

struct Host {
    GuestSpace space;
    hk::Kernel kernel;
    std::shared_ptr<hk::Process> process;
    ProcessInfo info;
    bool trace = false;

    std::mutex heap_mutex;
    uint64_t heap_size = 0;

    std::mutex threads_mutex;
    std::vector<std::unique_ptr<ThreadContext>> threads;
    uint64_t tls_used = 0;

    // Thread-local regions are 0x200 bytes, eight to a page, in a block at
    // the top of the stack region.
    static constexpr uint64_t kTlsBase = Layout::kStackBase + Layout::kStackSize - 0x1000000;

    uint64_t AllocateTls() {
        std::lock_guard lock(threads_mutex);
        const uint64_t address = kTlsBase + tls_used;
        if (tls_used % 0x1000 == 0 && !space.Map(address, 0x1000, kStateThreadLocal, kPermRW))
            return 0;
        tls_used += 0x200;
        return address;
    }

    // The kernel records a thread's own handle in its thread-local region,
    // where the guest's mutex code reads it to recognise its own locks.
    static constexpr uint64_t kTlsHandleOffset = 0x110;

    uint32_t AddHandle(ThreadContext& context) {
        const uint32_t handle = kernel.AddThreadHandle(context.kernel_thread);
        std::memcpy(space.base() + context.tls + kTlsHandleOffset, &handle, sizeof handle);
        return handle;
    }

    ThreadContext* NewThread(uint64_t entry, uint64_t argument, uint64_t stack_top) {
        const uint64_t tls = AllocateTls();
        if (!tls)
            return nullptr;
        auto context = std::make_unique<ThreadContext>();
        context->kernel_thread = kernel.CreateThread(process, tls);
        context->entry = entry;
        context->argument = argument;
        context->stack_top = stack_top;
        context->tls = tls;
        kernel.SetThreadUser(context->kernel_thread, context.get());
        std::lock_guard lock(threads_mutex);
        return threads.emplace_back(std::move(context)).get();
    }
};

Host* g_host;
thread_local Cpu* t_cpu;

void DumpRegisters(const Cpu& c);

LONG WINAPI OnFault(EXCEPTION_POINTERS* info) {
    const EXCEPTION_RECORD& r = *info->ExceptionRecord;
    if (r.ExceptionCode != EXCEPTION_ACCESS_VIOLATION || !t_cpu)
        return EXCEPTION_CONTINUE_SEARCH;
    auto host = static_cast<uint64_t>(r.ExceptionInformation[1]);
    auto base = reinterpret_cast<uint64_t>(g_host->space.base());
    std::fprintf(stderr, "guest fault: %s %016" PRIx64 " at pc %016" PRIx64 " (lr %016" PRIx64 ")\n",
                 r.ExceptionInformation[0] ? "write" : "read", host - base, t_cpu->pc, t_cpu->x[30]);
    DumpRegisters(*t_cpu);
    std::exit(3);
}

uint64_t AlignUp(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

// Runs a guest thread to completion on the calling host thread.
void RunThread(ThreadContext& context) {
    Cpu c{};
    c.mem = g_host->space.base();
    c.sp = context.stack_top;
    c.tpidrro = context.tls;
    c.host = &context;
    c.x[0] = context.argument;
    t_cpu = &c;
    try {
        Call(c, context.entry);
    } catch (const ThreadExit&) {
    }
    t_cpu = nullptr;
    g_host->kernel.DestroyThread(context.kernel_thread);
}

[[noreturn]] void Fail(const char* what) {
    std::fprintf(stderr, "module_host: %s\n", what);
    std::exit(3);
}

void DumpRegisters(const Cpu& c) {
    for (int i = 0; i < 31; i += 4) {
        for (int j = i; j < std::min(i + 4, 31); ++j)
            std::fprintf(stderr, "  x%-2d %016" PRIx64, j, c.x[j]);
        std::fprintf(stderr, "\n");
    }
    std::fprintf(stderr, "  sp  %016" PRIx64 "  nzcv %d%d%d%d\n", c.sp, c.nf, c.zf, c.cf, c.vf);
    if (g_host->space.IsMapped(c.tpidrro, 0x200)) {
        // nn::os keeps the thread's handle at +0x110 and its ThreadType at +0x1f8.
        uint32_t handle;
        uint64_t thread;
        std::memcpy(&handle, g_host->space.base() + c.tpidrro + 0x110, sizeof handle);
        std::memcpy(&thread, g_host->space.base() + c.tpidrro + 0x1f8, sizeof thread);
        std::fprintf(stderr, "  tls %016" PRIx64 "  handle %08x  thread %016" PRIx64 "\n", c.tpidrro, handle, thread);
    }
    // Guest frames: x29 points at {previous x29, return address}.
    std::fprintf(stderr, "  backtrace: %016" PRIx64, c.x[30]);
    uint64_t fp = c.x[29];
    for (int depth = 0; depth < 24 && fp && g_host->space.IsMapped(fp, 16); ++depth) {
        uint64_t frame[2];
        std::memcpy(frame, g_host->space.base() + fp, sizeof frame);
        std::fprintf(stderr, " %016" PRIx64, frame[1]);
        fp = frame[0];
    }
    std::fprintf(stderr, "\n");
}

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void LoadElf(GuestSpace& space, const std::string& path) {
    std::vector<uint8_t> data = ReadFile(path);
    if (data.size() < 64 || std::memcmp(data.data(), "\x7f" "ELF", 4) != 0) {
        std::fprintf(stderr, "module_host: %s is not an ELF\n", path.c_str());
        std::exit(3);
    }
    uint64_t phoff;
    uint16_t phnum;
    std::memcpy(&phoff, &data[0x20], 8);
    std::memcpy(&phnum, &data[0x38], 2);
    for (uint16_t i = 0; i < phnum; ++i) {
        const uint8_t* ph = &data[phoff + i * 56u];
        uint32_t type, flags;
        uint64_t offset, vaddr, filesz, memsz;
        std::memcpy(&type, ph, 4);
        std::memcpy(&flags, ph + 4, 4);
        std::memcpy(&offset, ph + 8, 8);
        std::memcpy(&vaddr, ph + 16, 8);
        std::memcpy(&filesz, ph + 32, 8);
        std::memcpy(&memsz, ph + 40, 8);
        if (type != 1)
            continue;
        uint32_t perm = (flags & 4 ? kPermR : 0) | (flags & 2 ? kPermW : 0) | (flags & 1 ? kPermX : 0);
        uint32_t state = flags & 2 ? kStateCodeData : kStateCode;
        if (!space.Map(vaddr, AlignUp(memsz, 0x1000), state, perm))
            Fail("could not map a segment");
        std::memcpy(space.base() + vaddr, &data[offset], filesz);
    }
}

// Loads the modules of a title as tools/nso.py --exefs laid them out, and
// reads the process's metadata from main.npdm.
void LoadTitle(GuestSpace& space, const std::string& folder, ProcessInfo& info) {
    std::ifstream layout(folder + "/layout.txt");
    if (!layout)
        Fail("no layout.txt in the title folder");
    std::string line;
    uint64_t first = 0;
    while (std::getline(layout, line)) {
        std::istringstream fields(line);
        std::string name;
        uint64_t base, size;
        if (line.empty() || line[0] == '#' || !(fields >> name >> std::hex >> base >> size))
            continue;
        LoadElf(space, folder + "/" + name + ".load.elf");
        std::fprintf(stderr, "loaded %-8s at %010" PRIx64 "\n", name.c_str(), base);
        if (!first)
            first = base;
    }
    // The lift's entry is the first module, rtld, which links the rest.
    if (first != rt_module_entry)
        Fail("the title's first module is not where the lift was entered");

    // META: flags at 0x0C (bits 1 to 3 the address space type), main thread
    // stack size at 0x1C, ACI0's offset at 0x70 and its program id at +0x10.
    std::vector<uint8_t> npdm = ReadFile(folder + "/main.npdm");
    if (npdm.size() < 0x80 || std::memcmp(npdm.data(), "META", 4) != 0)
        Fail("no main.npdm in the title folder");
    if ((npdm[0x0C] >> 1 & 7) != 3)
        Fail("only the 39-bit address space is laid out");
    uint32_t stack_size, aci_offset;
    std::memcpy(&stack_size, &npdm[0x1C], 4);
    std::memcpy(&aci_offset, &npdm[0x70], 4);
    if (aci_offset + 0x18 > npdm.size() || std::memcmp(&npdm[aci_offset], "ACI0", 4) != 0)
        Fail("main.npdm has no ACI0");
    std::memcpy(&info.program_id, &npdm[aci_offset + 0x10], 8);
    info.main_stack_size = stack_size;
    info.application = true;
    // The application pool of a 4 GB console.
    info.total_memory = 0xCD500000;
}

} // namespace

// Leaving lifted code ----------------------------------------------------------

void Call(Cpu& c, u64 target) {
    const FunctionEntry* begin = rt_functions;
    const FunctionEntry* end = rt_functions + rt_function_count;
    auto it = std::lower_bound(begin, end, target, [](const FunctionEntry& e, u64 a) { return e.address < a; });
    if (it == end || it->address != target) {
        std::fprintf(stderr, "call to %016" PRIx64 ", which is not a lifted entry point (lr %016" PRIx64 ")\n",
                     target, c.x[30]);
        DumpRegisters(c);
        std::exit(3);
    }
    it->function(c);
}

u64 CounterTicks() {
    LARGE_INTEGER now, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    // The guest counter runs at 19.2 MHz.
    return static_cast<u64>(static_cast<double>(now.QuadPart) * 19200000.0 / static_cast<double>(freq.QuadPart));
}

void Unimplemented(Cpu& c, u64 pc, u32 word) {
    std::fprintf(stderr, "unimplemented instruction %08x at %016" PRIx64 "\n", word, pc);
    DumpRegisters(c);
    std::exit(3);
}

void BadJump(Cpu& c, u64 pc, u64 target) {
    std::fprintf(stderr, "jump table at %016" PRIx64 " went to %016" PRIx64 ", outside its cases\n", pc, target);
    DumpRegisters(c);
    std::exit(3);
}

void Svc(Cpu& c, u32 id, u64 pc) {
    auto* thread = static_cast<ThreadContext*>(c.host);
    if (g_host->trace) {
        std::fprintf(stderr, "svc %02x at %016" PRIx64 " (%016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ")\n",
                     id, pc, c.x[0], c.x[1], c.x[2], c.x[3]);
    }
    hk_regs regs;
    std::memcpy(regs.x, c.x, sizeof regs.x);
    switch (id) {
    case HK_SVC_CLOSE_HANDLE:
    case HK_SVC_CONNECT_TO_NAMED_PORT:
    case HK_SVC_SEND_SYNC_REQUEST:
    case HK_SVC_CREATE_SESSION:
    case HK_SVC_ACCEPT_SESSION:
    case HK_SVC_REPLY_AND_RECEIVE:
    case HK_SVC_MANAGE_NAMED_PORT:
    case HK_SVC_SIGNAL_EVENT:
    case HK_SVC_CLEAR_EVENT:
    case HK_SVC_RESET_SIGNAL:
    case HK_SVC_WAIT_SYNCHRONIZATION:
    case HK_SVC_CANCEL_SYNCHRONIZATION:
    case HK_SVC_ARBITRATE_LOCK:
    case HK_SVC_ARBITRATE_UNLOCK:
    case HK_SVC_WAIT_PROCESS_WIDE_KEY_ATOMIC:
    case HK_SVC_SIGNAL_PROCESS_WIDE_KEY:
    case HK_SVC_GET_THREAD_ID:
    case HK_SVC_CREATE_EVENT:
    case HK_SVC_CREATE_SHARED_MEMORY:
    case HK_SVC_MAP_SHARED_MEMORY:
    case HK_SVC_UNMAP_SHARED_MEMORY:
    case HK_SVC_CREATE_TRANSFER_MEMORY:
        hk_svc(thread->kernel_thread, id, &regs);
        break;
    case 0x06: { // QueryMemory(MemoryInfo* out, PageInfo* out, address)
        Region r = g_host->space.Query(c.x[2]);
        struct {
            uint64_t address, size;
            uint32_t state, attribute, perm, ipc_refs, device_refs, padding;
        } info{r.address, r.size, r.state, 0, r.perm, 0, 0, 0};
        if (!g_host->space.Write(c.x[0], std::as_bytes(std::span(&info, 1)))) {
            regs.x[0] = hk::result::InvalidPointer;
            break;
        }
        regs.x[0] = 0;
        regs.x[1] = 0;
        break;
    }
    case 0x01: { // SetHeapSize(size) -> address
        const uint64_t size = c.x[1];
        std::lock_guard lock(g_host->heap_mutex);
        uint64_t& current = g_host->heap_size;
        bool ok = size % 0x200000 == 0 && size <= Layout::kHeapSize;
        if (ok && size > current)
            ok = g_host->space.Map(Layout::kHeapBase + current, size - current, kStateNormal, kPermRW);
        else if (ok && size < current)
            ok = g_host->space.Unmap(Layout::kHeapBase + size, current - size);
        if (!ok) {
            regs.x[0] = hk::MakeKernelResult(size % 0x200000 ? 102 : 103); // InvalidSize, OutOfMemory
            break;
        }
        current = size;
        regs.x[0] = 0;
        regs.x[1] = Layout::kHeapBase;
        break;
    }
    case 0x02: // SetMemoryPermission(address, size, perm)
    case 0x03: // SetMemoryAttribute(address, size, mask, value)
        // Guest permissions and attributes are not modelled; check the range.
        regs.x[0] = c.x[0] % 0x1000 || c.x[1] % 0x1000 || !g_host->space.IsMapped(c.x[0], c.x[1])
                        ? hk::result::InvalidCurrentMemory
                        : 0;
        break;
    case 0x04: { // MapMemory(destination, source, size)
        // Horizon aliases the pages and makes the source inaccessible until
        // UnmapMemory, so copying in and back out is equivalent.
        const uint64_t dst = c.x[0], src = c.x[1], size = c.x[2];
        auto& space = g_host->space;
        if (dst % 0x1000 || src % 0x1000 || size % 0x1000 || !size || !space.IsMapped(src, size)) {
            regs.x[0] = hk::result::InvalidCurrentMemory;
            break;
        }
        if (!space.Map(dst, size, kStateStack, kPermRW)) {
            regs.x[0] = hk::result::InvalidCurrentMemory;
            break;
        }
        std::memcpy(space.base() + dst, space.base() + src, size);
        regs.x[0] = 0;
        break;
    }
    case 0x05: { // UnmapMemory(destination, source, size)
        const uint64_t dst = c.x[0], src = c.x[1], size = c.x[2];
        auto& space = g_host->space;
        if (!space.IsMapped(dst, size) || !space.IsMapped(src, size)) {
            regs.x[0] = hk::result::InvalidCurrentMemory;
            break;
        }
        std::memcpy(space.base() + src, space.base() + dst, size);
        regs.x[0] = space.Unmap(dst, size) ? 0 : hk::result::InvalidCurrentMemory;
        break;
    }
    case 0x07: // ExitProcess
        std::fprintf(stderr, "guest exited\n");
        std::exit(0);
    case 0x08: { // CreateThread(entry, argument, stack_top, priority, core) -> handle
        ThreadContext* context = g_host->NewThread(c.x[1], c.x[2], c.x[3]);
        if (!context) {
            regs.x[0] = hk::MakeKernelResult(103); // OutOfMemory
            break;
        }
        regs.x[0] = 0;
        regs.x[1] = g_host->AddHandle(*context);
        break;
    }
    case 0x09: { // StartThread(handle)
        hk_thread* target = g_host->kernel.FindThread(thread->kernel_thread, static_cast<uint32_t>(c.x[0]));
        auto* context = target ? static_cast<ThreadContext*>(g_host->kernel.ThreadUser(target)) : nullptr;
        if (!context || context->host_thread.joinable()) {
            regs.x[0] = context ? hk::result::InvalidState : hk::result::InvalidHandle;
            break;
        }
        context->host_thread = std::thread([context] { RunThread(*context); });
        regs.x[0] = 0;
        break;
    }
    case 0x0A: // ExitThread
        throw ThreadExit{};
    case 0x0B: // SleepThread(ns)
        if (static_cast<int64_t>(c.x[0]) <= 0)
            SwitchToThread();
        else
            Sleep(static_cast<DWORD>((c.x[0] + 999999) / 1000000));
        regs.x[0] = 0;
        break;
    case 0x0C: // GetThreadPriority(handle)
        regs.x[0] = 0;
        regs.x[1] = 0x2C;
        break;
    case 0x0D: // SetThreadPriority(handle, priority)
    case 0x0F: // SetThreadCoreMask(handle, core, mask)
        regs.x[0] = 0;
        break;
    case 0x0E: // GetThreadCoreMask(handle) -> core, mask
        regs.x[0] = 0;
        regs.x[1] = 3;
        regs.x[2] = 1u << 3;
        break;
    case 0x10: // GetCurrentProcessorNumber
        regs.x[0] = 3;
        break;
    case 0x26: // Break(reason, info, size)
        std::fprintf(stderr, "guest Break(%#" PRIx64 ", %#" PRIx64 ", %#" PRIx64 ") at %016" PRIx64 "\n",
                     c.x[0], c.x[1], c.x[2], pc);
        if (c.x[2] == 4 && g_host->space.IsMapped(c.x[1], 4)) { // an abort passes its result code
            uint32_t code;
            std::memcpy(&code, g_host->space.base() + c.x[1], sizeof code);
            std::fprintf(stderr, "  result %08x (module %u, description %u)\n", code, code & 0x1ff, code >> 9);
        }
        DumpRegisters(c);
        std::exit(4);
    case 0x27: { // OutputDebugString(ptr, size)
        std::vector<char> text(static_cast<size_t>(std::min<uint64_t>(c.x[1], 0x10000)));
        if (g_host->space.Read(c.x[0], std::as_writable_bytes(std::span(text))))
            std::fprintf(stderr, "guest: %.*s\n", static_cast<int>(text.size()), text.data());
        regs.x[0] = 0;
        break;
    }
    case 0x29: { // GetInfo(type, handle, subtype) -> value
        uint64_t value = 0;
        switch (static_cast<uint32_t>(c.x[1])) {
        case 0: value = 0xF; break;                    // core mask
        case 1: value = ~uint64_t{0}; break;           // priority mask
        case 2: value = Layout::kAliasBase; break;
        case 3: value = Layout::kAliasSize; break;
        case 4: value = Layout::kHeapBase; break;
        case 5: value = Layout::kHeapSize; break;
        case 6: case 21: value = g_host->info.total_memory; break;
        case 7: case 22: {                             // used memory: the heap and a little
            std::lock_guard lock(g_host->heap_mutex);
            value = g_host->heap_size + 0x01000000;
            break;
        }
        case 8: value = 0; break;                      // debugger attached
        case 11: value = 0x0123456789ABCDEFull * (c.x[3] + 1); break; // random entropy
        case 12: value = Layout::kAslrBase; break;
        case 13: value = Layout::kAslrSize; break;
        case 14: value = Layout::kStackBase; break;
        case 15: value = Layout::kStackSize; break;
        case 16: case 17: value = 0; break;            // system resource size
        case 18: value = g_host->info.program_id; break;
        case 20: value = 0; break;                     // user exception context
        case 23: value = g_host->info.application; break;
        case 24: value = 0x100; break;                 // free thread count
        case 28: value = 0; break;                     // alias region extra size
        case 37: case 38: value = 0; break;            // an extra region's address and size: none
        default:
            std::fprintf(stderr, "GetInfo type %" PRIu64 " not implemented\n", c.x[1]);
            std::exit(3);
        }
        regs.x[0] = 0;
        regs.x[1] = value;
        break;
    }
    default:
        std::fprintf(stderr, "unimplemented svc %#x at %016" PRIx64 "\n", id, pc);
        DumpRegisters(c);
        std::exit(3);
    }
    std::memcpy(c.x, regs.x, sizeof regs.x);
    if (g_host->trace)
        std::fprintf(stderr, "    -> %08x %016" PRIx64 "\n", static_cast<uint32_t>(c.x[0]), c.x[1]);
}

} // namespace rt

int main(int argc, char** argv) {
    using namespace rt;
    const auto usage = [] {
        std::fprintf(stderr, "usage: module_host [--link <read> <write>] "
                             "[--application <pid> <program id> <version> <control.nacp>] "
                             "{<module.elf> [main-thread-stack-size] | --title <folder> [--romfs <image>]}\n");
        std::exit(2);
    };
    uintptr_t link_read = 0, link_write = 0;
    const char* title = nullptr;
    services::StubOptions stub_options;
    int arg = 1;
    for (; arg < argc && std::strncmp(argv[arg], "--", 2) == 0; ++arg) {
        const std::string option = argv[arg];
        if (option == "--link" && arg + 2 < argc) {
            link_read = static_cast<uintptr_t>(std::strtoull(argv[arg + 1], nullptr, 10));
            link_write = static_cast<uintptr_t>(std::strtoull(argv[arg + 2], nullptr, 10));
            arg += 2;
        } else if (option == "--application" && arg + 4 < argc) {
            services::Application application;
            application.process_id = std::strtoull(argv[arg + 1], nullptr, 0);
            application.program_id = std::strtoull(argv[arg + 2], nullptr, 16);
            application.version = static_cast<uint32_t>(std::strtoul(argv[arg + 3], nullptr, 0));
            std::ifstream control(argv[arg + 4], std::ios::binary);
            application.control.resize(0x4000);
            if (!control.read(reinterpret_cast<char*>(application.control.data()), 0x4000))
                Fail("could not read 0x4000 bytes of application control data");
            stub_options.application = std::move(application);
            arg += 4;
        } else if (option == "--title" && arg + 1 < argc) {
            title = argv[++arg];
        } else if (option == "--romfs" && arg + 1 < argc) {
            stub_options.romfs = argv[++arg];
        } else {
            usage();
        }
    }
    if (title ? arg != argc : arg >= argc)
        usage();

    Host host;
    g_host = &host;
    char trace[8] = {};
    host.trace = GetEnvironmentVariableA("RT_TRACE", trace, sizeof trace) > 0 && trace[0] != '0';
    if (title) {
        LoadTitle(host.space, title, host.info);
    } else {
        LoadElf(host.space, argv[arg]);
        if (arg + 1 < argc)
            host.info.main_stack_size = std::strtoull(argv[arg + 1], nullptr, 0);
    }
    const uint64_t stack_size = AlignUp(host.info.main_stack_size, 0x1000);

    const uint64_t stack = Layout::kStackBase;
    if (!host.space.Map(stack, stack_size, kStateStack, kPermRW))
        Fail("could not map the main thread's stack");
    host.process = host.kernel.CreateProcess(0x50, host.space);
    services::ServiceManager sm(host.kernel, host.trace);
    services::NativeHost stubs(host.kernel, host.trace);
    stub_options.trace = host.trace;
    char boot_mode[8] = {};
    if (GetEnvironmentVariableA("RT_BOOT_MODE", boot_mode, sizeof boot_mode) > 0)
        stub_options.boot_mode = static_cast<uint32_t>(std::strtoul(boot_mode, nullptr, 0));
    services::AddStubs(stubs, stub_options);
    if (host.info.application)
        services::AddApplicationServices(stubs, {host.info.program_id, host.trace});
    stubs.Start();
    char probe[8] = {};
    if (GetEnvironmentVariableA("RT_PROBE", probe, sizeof probe) > 0 && probe[0] != '0')
        services::StartPctlProbe(host.kernel);
    if (link_read)
        host.kernel.AttachLink(hk::OpenPipeStream(link_read, link_write), false);
    AddVectoredExceptionHandler(1, OnFault);

    // The kernel starts the main thread at the module entry with x0 = 0 and
    // x1 = the thread's own handle.
    ThreadContext* main_thread = host.NewThread(rt_module_entry, 0, stack + stack_size);
    if (!main_thread)
        Fail("could not create the main thread");
    const uint32_t handle = host.AddHandle(*main_thread);
    Cpu c{};
    c.mem = host.space.base();
    c.sp = main_thread->stack_top;
    c.tpidrro = main_thread->tls;
    c.host = main_thread;
    c.x[1] = handle;
    t_cpu = &c;
    try {
        Call(c, rt_module_entry);
        std::fprintf(stderr, "module entry returned %016" PRIx64 "\n", c.x[0]);
    } catch (const ThreadExit&) {
        std::fprintf(stderr, "main thread exited\n");
    }
    return 0;
}
