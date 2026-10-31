// module_host: runs a lifted sysmodule, or a lifted title, against the host
// kernel.
//
// Usage: module_host [options] <module.elf> [main-thread-stack-size]
//        module_host [options] --title <folder>
//
// A sysmodule's program id and main thread stack size come from the
// main.npdm next to its ELF, if there is one.
//
// Options:
//   --link <read> <write>   serve over a link to the parent host process, on
//                           two inherited pipe handles; the ports the module
//                           registers become reachable from the parent
//   --process-id <id>       the process id the kernel gives the module
//   --log-prefix <name>     start every line of output with "<name>: "; the
//                           sysmodules started from here get their names
//   --omit <name>,...       leave out these stub services, which other
//                           recompiled sysmodules host
//   --sysmodule <host> <module.elf>
//                           start <host>, a module_host built with that
//                           sysmodule's lift, as a linked child process
//                           running it; repeatable. Each child's ports are
//                           reachable from this process and from the other
//                           children, through this process's kernel
//   --application <pid> <program id> <version> <control.nacp>
//                           the application arp:r reports for that process
//   --launch                with --title: start the title only when ns
//                           launches it. The host asks ns, as am does, to
//                           acquire the title's launch info and launch it,
//                           and the title's main thread starts when ns
//                           calls pgl LaunchProgram for it
//   --title <folder>        run an application: every module tools/nso.py
//                           --exefs laid out in the folder (layout.txt and the
//                           <name>.load.elf files), with the program id, main
//                           thread and address space from its main.npdm
//   --romfs <image>         the title's RomFS image (tools/nca.py --romfs),
//                           served by fsp-srv as its data storage
//   --system-data <folder>  the firmware's system data archives
//                           (tools/nca.py --system-data <folder> all), which
//                           fsp-srv serves by data id; passed on to children
//   --content <folder>      the content index (tools/nca.py --content-index)
//                           that ncm and lr serve; the children use this host's
//   --calibration <file>    the console's calibration data (a CAL0 image,
//                           tools/calibration.py), served by fsp-srv as BIS
//                           partition 27; passed on to children
//
// The ELF is the module as tools/nso.py --no-relocate writes it: the same
// image the lift came from, but with relocations left for the module's own
// startup code to apply. Segments load at their link addresses. Set
// RT_TRACE=1 to log every supervisor call, RT_BOOT_MODE to choose what pm:bm
// reports (default 0, normal), RT_PROBE=1 to check that the module
// serves pctl and exit (see services/probe.h), and RT_PEEK=<address>,... to
// print those guest words with a fault's registers.
#include "guest_space.h"
#include "hk/kernel.h"
#include "hk/link.h"
#include "kernel/platform.h"
#include "rt/ops.h"
#include "services/application.h"
#include "services/content.h"
#include "services/probe.h"
#include "services/sm.h"
#include "services/stubs.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <map>
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
#include <fcntl.h>
#include <io.h>

namespace rt {

namespace {

// Thrown by ExitThread to unwind a guest thread back to its host thread root.
struct ThreadExit {};

struct Core;

struct ThreadContext {
    hk_thread* kernel_thread{};
    uint64_t entry{}, argument{}, stack_top{}, tls{};
    int32_t priority{}, core{};
    Core* on{}; // the core this thread runs on, while it holds it
    std::thread host_thread;
};

// One of the console's four cores. The threads placed on a core run guest
// code one at a time, the highest priority (lowest number) first, as
// Horizon schedules them; modules rely on that, for one by finishing their
// set-up before a thread they start at a lower priority runs. A thread gives
// up its core for every supervisor call and takes it back afterwards, so a
// thread of higher priority that became ready meanwhile goes first; that is
// the only preemption. Threads on different cores run in parallel.
//
// Sysmodules share core 3 across processes on the console, and a request to
// another process runs its server on the same core at once and comes back:
// threads of the client below the requester's priority do not run in
// between. Each host process has cores of its own, so a thread waiting for a
// reply keeps its priority on its core (Hold) for a short while, long enough
// for a server that answers at once.
struct Core {
    std::mutex mutex;
    std::condition_variable changed;
    bool busy = false;
    const ThreadContext* running{};
    const ThreadContext* holder{}; // waiting for a reply, see above
    int32_t held_priority{};
    std::chrono::steady_clock::time_point held_until;
    struct Ready {
        ThreadContext* thread;
        int64_t order; // among equal priorities, the lowest goes first
    };
    std::vector<Ready> ready;
    int64_t arrivals = 0, resumptions = 0;

    // Waits for the core. A thread resuming after a call that did not
    // block goes ahead of the threads of its own priority, as on Horizon,
    // where it would not have left the core.
    void Enter(ThreadContext& t, bool resuming) {
        std::unique_lock lock(mutex);
        if (holder == &t)
            holder = nullptr;
        ready.push_back({&t, resuming ? --resumptions : ++arrivals});
        auto waited = std::chrono::steady_clock::now();
        while (busy || Next() != &t) {
            const auto now = std::chrono::steady_clock::now();
            if (holder && now >= held_until)
                holder = nullptr;
            if (now - waited >= std::chrono::seconds(2)) {
                waited = now;
                std::fprintf(stderr, "core: thread at %016" PRIx64 " (priority %d) has waited 2 s; %s %016" PRIx64 "\n",
                             t.entry, t.priority, busy ? "the core runs the thread at" : "next is",
                             busy && running ? running->entry : 0);
            }
            changed.wait_until(lock, holder ? std::min(held_until, now + std::chrono::seconds(2))
                                            : now + std::chrono::seconds(2));
        }
        std::erase_if(ready, [&](const Ready& r) { return r.thread == &t; });
        busy = true;
        running = &t;
        t.on = this;
    }
    // hold: the thread is waiting for a reply and keeps its priority here.
    void Leave(ThreadContext& t, bool hold = false) {
        {
            std::lock_guard lock(mutex);
            busy = false;
            running = nullptr;
            t.on = nullptr;
            if (hold) {
                holder = &t;
                held_priority = t.priority;
                held_until = std::chrono::steady_clock::now() + std::chrono::milliseconds(2);
            }
        }
        changed.notify_all();
    }
    ThreadContext* Next() const {
        const bool holding = holder && std::chrono::steady_clock::now() < held_until;
        const Ready* best = nullptr;
        for (const auto& r : ready) {
            if (holding && r.thread->priority >= held_priority)
                continue;
            if (!best || r.thread->priority < best->thread->priority ||
                (r.thread->priority == best->thread->priority && r.order < best->order))
                best = &r;
        }
        return best ? best->thread : nullptr;
    }
};

// What GetInfo and the main thread need to know about the process.
struct ProcessInfo {
    uint64_t program_id = 0x010000000000002E; // pctl, the first module run
    bool application = false;
    uint64_t main_stack_size = 0x10000;
    uint64_t total_memory = 0x10000000;
    int32_t main_priority = 44, default_core = 3;
    std::vector<std::string> hosted; // the services its NPDM lets it host
};

struct Host {
    GuestSpace space;
    hk::Kernel kernel;
    std::shared_ptr<hk::Process> process;
    ProcessInfo info;
    bool trace = false;

    std::mutex heap_mutex;
    uint64_t heap_size = 0;

    std::array<Core, 4> cores;
    Core& CoreOf(const ThreadContext& t) { return cores[static_cast<size_t>(t.core) & 3]; }

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

    ThreadContext* NewThread(uint64_t entry, uint64_t argument, uint64_t stack_top, int32_t priority, int32_t core) {
        const uint64_t tls = AllocateTls();
        if (!tls)
            return nullptr;
        auto context = std::make_unique<ThreadContext>();
        context->kernel_thread = kernel.CreateThread(process, tls);
        context->entry = entry;
        context->argument = argument;
        context->stack_top = stack_top;
        context->tls = tls;
        context->priority = priority;
        context->core = core >= 0 && core < 4 ? core : info.default_core; // -2: the process's default core
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
    g_host->CoreOf(context).Enter(context, false);
    try {
        Call(c, context.entry);
    } catch (const ThreadExit&) {
    }
    t_cpu = nullptr;
    if (context.on) // not when ExitThread left it
        context.on->Leave(context);
    g_host->kernel.DestroyThread(context.kernel_thread);
}

[[noreturn]] void Fail(const char* what) {
    std::fprintf(stderr, "module_host: %s\n", what);
    std::exit(3);
}

// Guest frames: x29 points at {previous x29, return address}.
void PrintBacktrace(const Cpu& c) {
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
    // RT_PEEK=<address>,...: guest words worth seeing at a failure.
    char peek[256] = {};
    if (GetEnvironmentVariableA("RT_PEEK", peek, sizeof peek) > 0) {
        for (char* next = peek; *next;) {
            const uint64_t address = std::strtoull(next, &next, 16);
            uint64_t value = 0;
            if (g_host->space.IsMapped(address, 8))
                std::memcpy(&value, g_host->space.base() + address, sizeof value);
            std::fprintf(stderr, "  [%016" PRIx64 "] = %016" PRIx64 "\n", address, value);
            while (*next == ',')
                ++next;
        }
    }
    PrintBacktrace(c);
}

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Prefixes every line this process writes to stderr, so that a sysmodule
// host's output can be told from its parent's. A thread forwards the lines;
// at exit, stderr closes and the thread finishes the last of them.
std::thread g_prefixer;

void PrefixStderr(const std::string& prefix) {
    int pipe[2];
    if (_pipe(pipe, 0x10000, _O_BINARY) != 0)
        return;
    const int original = _dup(2);
    _dup2(pipe[1], 2);
    _close(pipe[1]);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    g_prefixer = std::thread([read = pipe[0], original, prefix] {
        std::string line = prefix + ": ";
        char buffer[4096];
        for (int n; (n = _read(read, buffer, sizeof buffer)) > 0;) {
            for (int i = 0; i < n; ++i) {
                line.push_back(buffer[i]);
                if (buffer[i] == '\n') {
                    _write(original, line.data(), static_cast<unsigned>(line.size()));
                    line.resize(prefix.size() + 2);
                }
            }
        }
    });
    std::atexit([] {
        std::fflush(stderr);
        _close(2);
        if (g_prefixer.joinable())
            g_prefixer.join();
    });
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

// Reads the program id and main thread stack size from a main.npdm.
// META: flags at 0x0C (bits 1 to 3 the address space type), the main
// thread's priority and core at 0x0E and 0x0F, its stack size at 0x1C,
// ACI0's offset at 0x70 and its program id at +0x10.
void ReadNpdm(const std::string& path, ProcessInfo& info) {
    std::vector<uint8_t> npdm = ReadFile(path);
    if (npdm.size() < 0x80 || std::memcmp(npdm.data(), "META", 4) != 0)
        Fail("not an NPDM");
    if ((npdm[0x0C] >> 1 & 7) != 3)
        Fail("only the 39-bit address space is laid out");
    uint32_t stack_size, aci_offset;
    std::memcpy(&stack_size, &npdm[0x1C], 4);
    std::memcpy(&aci_offset, &npdm[0x70], 4);
    if (aci_offset + 0x18 > npdm.size() || std::memcmp(&npdm[aci_offset], "ACI0", 4) != 0)
        Fail("the NPDM has no ACI0");
    std::memcpy(&info.program_id, &npdm[aci_offset + 0x10], 8);
    info.main_stack_size = stack_size;
    info.main_priority = npdm[0x0E];
    info.default_core = npdm[0x0F];
    // Service access control: a control byte (bit 7 set for a service it
    // hosts, the name's length less one in bits 0 to 2) and then the name.
    uint32_t sac_offset, sac_size;
    std::memcpy(&sac_offset, &npdm[aci_offset + 0x28], 4);
    std::memcpy(&sac_size, &npdm[aci_offset + 0x2C], 4);
    const size_t sac = aci_offset + sac_offset, end = std::min<size_t>(sac + sac_size, npdm.size());
    info.hosted.clear();
    for (size_t i = sac; i < end;) {
        const uint8_t control = npdm[i];
        const size_t length = (control & 7u) + 1;
        if (i + 1 + length > end)
            break;
        if (control & 0x80)
            info.hosted.emplace_back(reinterpret_cast<const char*>(&npdm[i + 1]), length);
        i += 1 + length;
    }
}

// Sysmodules started from a host get process ids from here on, below the
// application's, as on the console.
constexpr uint64_t kFirstSysmoduleId = 0x20;

// The main.npdm beside a module's ELF, if there is one.
std::string NpdmBeside(const std::string& elf) {
    return (std::filesystem::path(elf).parent_path() / "main.npdm").string();
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

    if (!std::ifstream(folder + "/main.npdm"))
        Fail("no main.npdm in the title folder");
    ReadNpdm(folder + "/main.npdm", info);
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

// Guest contexts (fibers) --------------------------------------------------
//
// Lifted code returns through the host stack, so a guest context switch
// becomes a host fiber switch: each suspended context is a host fiber, kept
// under the guest sp it left. A context may be resumed by another guest
// thread than the one that left it, so each has CPU state of its own (its
// lifted frames refer to it), and a switch copies the switching thread's
// state into it, as the registers carry across on the console; the switch's
// own code then restores the rest from the context's stack.

namespace {

struct Context {
    void* fiber;
    Cpu* cpu;
};

std::mutex g_contexts_mutex;
std::map<u64, Context> g_contexts; // suspended contexts by guest sp

struct NewContext {
    Cpu* cpu; // owned by the context from here on
    u64 resume;
};

// A context's first run: the rest of the switch restores its registers from
// its stack and returns to its x30, the context's function, which never
// returns.
void WINAPI ContextMain(void* parameter) {
    const NewContext start = *static_cast<NewContext*>(parameter);
    delete static_cast<NewContext*>(parameter);
    Cpu& c = *start.cpu;
    t_cpu = &c;
    Call(c, start.resume);
    Call(c, c.x[30]);
    std::fprintf(stderr, "a guest context's function returned (sp %016" PRIx64 ")\n", c.sp);
    DumpRegisters(c);
    std::exit(3);
}

} // namespace

void SwitchStack(Cpu& c, u64 previous, u64 resume) {
    if (!IsThreadAFiber())
        ConvertThreadToFiber(nullptr);
    Context target{};
    {
        std::lock_guard lock(g_contexts_mutex);
        g_contexts[previous] = {GetCurrentFiber(), &c};
        if (auto it = g_contexts.find(c.sp); it != g_contexts.end()) {
            target = it->second;
            g_contexts.erase(it);
        }
    }
    if (g_host->trace)
        std::fprintf(stderr, "    context switch from sp %016" PRIx64 " to %016" PRIx64 "%s\n", previous, c.sp,
                     target.fiber ? "" : ", a new context");
    if (target.fiber) {
        *target.cpu = c;
    } else {
        // 64 KB committed, 8 MB reserved: lifted code is deep on the host stack.
        target.fiber = CreateFiberEx(0x10000, 0x800000, FIBER_FLAG_FLOAT_SWITCH, ContextMain,
                                     new NewContext{new Cpu(c), resume});
        if (!target.fiber)
            Fail("could not create a fiber for a guest context");
    }
    SwitchToFiber(target.fiber);
    // Back in this context, with the state of the thread that switched here.
    t_cpu = &c;
}

void Svc(Cpu& c, u32 id, u64 pc) {
    auto* thread = static_cast<ThreadContext*>(c.host);
    if (g_host->trace) {
        // Threads are told apart by their TLS, which follows the svc.
        std::fprintf(stderr, "svc %02x at %016" PRIx64 " (%016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ") tls %" PRIx64 "\n",
                     id, pc, c.x[0], c.x[1], c.x[2], c.x[3], c.tpidrro & 0xffffff);
        if (id == HK_SVC_WAIT_SYNCHRONIZATION && c.x[2] <= 0x40 && g_host->space.IsMapped(c.x[1], c.x[2] * 4)) {
            std::fprintf(stderr, "    handles");
            for (u64 i = 0; i < c.x[2]; ++i) {
                uint32_t handle;
                std::memcpy(&handle, g_host->space.base() + c.x[1] + i * 4, sizeof handle);
                std::fprintf(stderr, " %08x", handle);
            }
            std::fprintf(stderr, "\n");
            // A wait with no timeout: where from, to follow a thread that stops.
            if (c.x[3] == ~u64{0})
                PrintBacktrace(c);
        }
    }
    if (g_host->trace && id == HK_SVC_REPLY_AND_RECEIVE && c.x[3] != 0) {
        // A reply the module sends: its CMIF result follows the "SFCO" magic.
        uint32_t words[64];
        std::memcpy(words, g_host->space.base() + c.tpidrro, sizeof words);
        for (int i = 2; i + 2 < 64; ++i) {
            if (words[i] == 0x4F434653) {
                std::fprintf(stderr, "    replying %08x\n", words[i + 2]);
                break;
            }
        }
    }
    hk_regs regs;
    std::memcpy(regs.x, c.x, sizeof regs.x);
    // The core is free while the call runs; the thread takes it back below.
    // A call that may block, or a yield, returns it to the back of its
    // priority's queue.
    thread->on->Leave(*thread, id == HK_SVC_SEND_SYNC_REQUEST);
    bool may_block = false;
    switch (id) {
    case HK_SVC_SEND_SYNC_REQUEST:
    case HK_SVC_REPLY_AND_RECEIVE:
    case HK_SVC_WAIT_SYNCHRONIZATION:
    case HK_SVC_ARBITRATE_LOCK:
    case HK_SVC_WAIT_PROCESS_WIDE_KEY_ATOMIC:
    case HK_SVC_CONNECT_TO_NAMED_PORT:
    case 0x0B: // SleepThread
        may_block = true;
        break;
    }
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
        ThreadContext* context = g_host->NewThread(c.x[1], c.x[2], c.x[3], static_cast<int32_t>(c.x[4]),
                                                   static_cast<int32_t>(c.x[5]));
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
        if (g_host->trace)
            std::fprintf(stderr, "    thread at %016" PRIx64 ": priority %d, core %d\n", context->entry,
                         context->priority, context->core);
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
    case 0x0C:   // GetThreadPriority(handle) -> priority
    case 0x0D:   // SetThreadPriority(handle, priority)
    case 0x0E:   // GetThreadCoreMask(handle) -> core, mask
    case 0x0F: { // SetThreadCoreMask(handle, core, mask)
        // A new core applies from the thread's next supervisor call.
        const uint32_t handle = static_cast<uint32_t>(id == 0x0C ? c.x[1] : id == 0x0E ? c.x[2] : c.x[0]);
        hk_thread* target = g_host->kernel.FindThread(thread->kernel_thread, handle);
        auto* context = target ? static_cast<ThreadContext*>(g_host->kernel.ThreadUser(target)) : nullptr;
        if (!context) {
            regs.x[0] = hk::result::InvalidHandle;
            break;
        }
        regs.x[0] = 0;
        if (id == 0x0C) {
            regs.x[1] = static_cast<uint32_t>(context->priority);
        } else if (id == 0x0D) {
            context->priority = static_cast<int32_t>(c.x[1]);
        } else if (id == 0x0E) {
            regs.x[1] = static_cast<uint32_t>(context->core);
            regs.x[2] = uint64_t{1} << context->core;
        } else if (static_cast<int32_t>(c.x[1]) >= 0) { // -1 and -3 keep the ideal core
            context->core = static_cast<int32_t>(c.x[1]);
        }
        break;
    }
    case 0x10: // GetCurrentProcessorNumber
        regs.x[0] = static_cast<uint32_t>(thread->core);
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
    g_host->CoreOf(*thread).Enter(*thread, !may_block);
    std::memcpy(c.x, regs.x, sizeof regs.x);
    if (g_host->trace)
        std::fprintf(stderr, "    -> %08x %016" PRIx64 " tls %" PRIx64 "\n", static_cast<uint32_t>(c.x[0]), c.x[1],
                     c.tpidrro & 0xffffff);
    if (g_host->trace && id == HK_SVC_SEND_SYNC_REQUEST && c.x[0] == 0) {
        // The handles the reply carried, as this process numbers them.
        uint32_t words[16];
        std::memcpy(words, g_host->space.base() + c.tpidrro, sizeof words);
        if (words[1] & 0x80000000) {
            const uint32_t descriptor = words[2];
            const uint32_t count = ((descriptor >> 1) & 15) + ((descriptor >> 5) & 15);
            const uint32_t first = 3 + (descriptor & 1 ? 2 : 0);
            std::fprintf(stderr, "    got handles");
            for (uint32_t i = 0; i < count && first + i < 16; ++i)
                std::fprintf(stderr, " %08x", words[first + i]);
            std::fprintf(stderr, "\n");
        }
    }
    if (g_host->trace && id == HK_SVC_REPLY_AND_RECEIVE && c.x[0] == 0) {
        // A request the module received: name its CMIF command, found after
        // the "SFCI" magic in the thread's message buffer.
        uint32_t words[64];
        std::memcpy(words, g_host->space.base() + c.tpidrro, sizeof words);
        for (int i = 2; i + 7 < 64; ++i) {
            if (words[i] == 0x49434653) {
                std::fprintf(stderr, "    received command %u (type %u) args %08x %08x %08x %08x\n", words[i + 2], words[0] & 0xFFFF,
                             words[i + 4], words[i + 5], words[i + 6], words[i + 7]);
                break;
            }
        }
    }
}

} // namespace rt

int main(int argc, char** argv) {
    using namespace rt;
    const auto usage = [] {
        std::fprintf(stderr, "usage: module_host [--link <read> <write>] [--process-id <id>] "
                             "[--application <pid> <program id> <version> <control.nacp>] "
                             "[--sysmodule <host> <module.elf>]... "
                             "{<module.elf> [main-thread-stack-size] | --title <folder> [--romfs <image>]}\n");
        std::exit(2);
    };
    uintptr_t link_read = 0, link_write = 0;
    const char* title = nullptr;
    bool launch = false; // through ns
    uint64_t process_id = 0x50;
    std::string content; // the content index, for ncm and lr
    services::StubOptions stub_options;
    struct Sysmodule {
        std::string host, elf;
    };
    std::vector<Sysmodule> sysmodules;
    std::vector<std::string> application_arguments; // passed on to sysmodules
    std::vector<std::string> omitted; // stubs that recompiled sysmodules replace
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
            application_arguments.assign(argv + arg, argv + arg + 5);
            arg += 4;
        } else if (option == "--omit" && arg + 1 < argc) {
            std::istringstream names(argv[++arg]);
            for (std::string name; std::getline(names, name, ',');)
                omitted.push_back(name);
        } else if (option == "--log-prefix" && arg + 1 < argc) {
            PrefixStderr(argv[++arg]);
        } else if (option == "--process-id" && arg + 1 < argc) {
            process_id = std::strtoull(argv[++arg], nullptr, 0);
        } else if (option == "--sysmodule" && arg + 2 < argc) {
            sysmodules.push_back({argv[arg + 1], argv[arg + 2]});
            arg += 2;
        } else if (option == "--title" && arg + 1 < argc) {
            title = argv[++arg];
        } else if (option == "--launch") {
            launch = true;
        } else if (option == "--romfs" && arg + 1 < argc) {
            stub_options.romfs = argv[++arg];
        } else if (option == "--system-data" && arg + 1 < argc) {
            stub_options.system_data = argv[++arg];
        } else if (option == "--content" && arg + 1 < argc) {
            content = argv[++arg];
        } else if (option == "--calibration" && arg + 1 < argc) {
            stub_options.calibration = argv[++arg];
        } else {
            usage();
        }
    }
    if (title ? arg != argc : arg >= argc || launch)
        usage();

    Host host;
    g_host = &host;
    char trace[8] = {};
    host.trace = GetEnvironmentVariableA("RT_TRACE", trace, sizeof trace) > 0 && trace[0] != '0';
    if (title) {
        LoadTitle(host.space, title, host.info);
    } else {
        LoadElf(host.space, argv[arg]);
        const std::string npdm = NpdmBeside(argv[arg]);
        if (std::ifstream(npdm))
            ReadNpdm(npdm, host.info);
        if (arg + 1 < argc)
            host.info.main_stack_size = std::strtoull(argv[arg + 1], nullptr, 0);
    }
    const uint64_t stack_size = AlignUp(host.info.main_stack_size, 0x1000);

    const uint64_t stack = Layout::kStackBase;
    if (!host.space.Map(stack, stack_size, kStateStack, kPermRW))
        Fail("could not map the main thread's stack");
    host.process = host.kernel.CreateProcess(process_id, host.space);
    services::ServiceManager sm(host.kernel, host.trace);
    // A server thread waits on at most 0x40 handles, as on the console, so
    // the native services are spread over three hosts, each with its thread:
    // the stubs, the application's services, and content management.
    services::NativeHost stubs(host.kernel, host.trace);
    services::NativeHost application_services(host.kernel, host.trace);
    services::NativeHost content_services(host.kernel, host.trace);
    stub_options.trace = host.trace;
    char boot_mode[8] = {};
    if (GetEnvironmentVariableA("RT_BOOT_MODE", boot_mode, sizeof boot_mode) > 0)
        stub_options.boot_mode = static_cast<uint32_t>(std::strtoul(boot_mode, nullptr, 0));
    // What this module and the sysmodules started from here host replaces
    // the stubs of the same names, here and in every child.
    omitted.insert(omitted.end(), host.info.hosted.begin(), host.info.hosted.end());
    // The root host knows every process and serves pm:info for all of them.
    if (!sysmodules.empty())
        stub_options.processes[process_id] = host.info.program_id;
    for (size_t i = 0; i < sysmodules.size(); ++i) {
        ProcessInfo info;
        if (!std::ifstream(NpdmBeside(sysmodules[i].elf)))
            Fail((sysmodules[i].elf + " has no main.npdm beside it").c_str());
        ReadNpdm(NpdmBeside(sysmodules[i].elf), info);
        omitted.insert(omitted.end(), info.hosted.begin(), info.hosted.end());
        stub_options.processes[kFirstSysmoduleId + i] = info.program_id;
    }
    // pgl LaunchProgram for the title releases its main thread; the host runs
    // nothing else.
    std::promise<void> launched;
    std::once_flag launched_once;
    if (launch)
        stub_options.launch = [&, program_id = host.info.program_id](uint64_t program) -> std::optional<uint64_t> {
            if (program != program_id)
                return std::nullopt;
            std::call_once(launched_once, [&] { launched.set_value(); });
            return process_id;
        };
    services::AddStubs(stubs, stub_options);
    if (host.info.application)
        services::AddApplicationServices(application_services, {host.info.program_id, host.trace});
    services::AddContentServices(content_services, content, host.trace);
    std::vector<std::string> replaced = application_services.Names();
    for (const auto& name : content_services.Names())
        replaced.push_back(name);
    replaced.insert(replaced.end(), omitted.begin(), omitted.end());
    stubs.Omit(replaced);
    application_services.Omit(omitted);
    content_services.Omit(omitted);
    if (!sysmodules.empty()) // the children use this host's process and content services
        omitted.insert(omitted.end(), {"pm:info", "pgl", "ncm", "lr", "arp:r", "arp:w"});
    for (auto* services : {&stubs, &application_services, &content_services})
        if (!services->Names().empty())
            services->Start();
    char probe[8] = {};
    if (GetEnvironmentVariableA("RT_PROBE", probe, sizeof probe) > 0 && probe[0] != '0')
        services::StartPctlProbe(host.kernel);
    if (link_read)
        host.kernel.AttachLink(hk::OpenPipeStream(link_read, link_write), false);
    std::vector<std::unique_ptr<hk::platform::LinkedProcess>> children;
    for (size_t i = 0; i < sysmodules.size(); ++i) {
        std::string names;
        for (const auto& name : omitted)
            names += (names.empty() ? "" : ",") + name;
        std::vector<std::string> arguments{"--log-prefix", std::filesystem::path(sysmodules[i].elf).stem().stem().string(),
                                           "--process-id", std::to_string(kFirstSysmoduleId + i), "--omit", names};
        if (!stub_options.system_data.empty())
            arguments.insert(arguments.end(), {"--system-data", stub_options.system_data});
        if (!stub_options.calibration.empty())
            arguments.insert(arguments.end(), {"--calibration", stub_options.calibration});
        arguments.insert(arguments.end(), application_arguments.begin(), application_arguments.end());
        arguments.push_back(sysmodules[i].elf);
        try {
            children.push_back(std::make_unique<hk::platform::LinkedProcess>(sysmodules[i].host, arguments));
        } catch (const std::exception& e) {
            Fail((sysmodules[i].elf + ": " + e.what()).c_str());
        }
        host.kernel.AttachLink(children.back()->TakeStream(), true);
    }
    AddVectoredExceptionHandler(1, OnFault);
    if (launch) {
        services::StartLaunch(host.kernel, host.info.program_id, content);
        launched.get_future().wait();
    }

    // The kernel starts the main thread at the module entry with x0 = 0 and
    // x1 = the thread's own handle.
    ThreadContext* main_thread =
        host.NewThread(rt_module_entry, 0, stack + stack_size, host.info.main_priority, host.info.default_core);
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
    host.CoreOf(*main_thread).Enter(*main_thread, false);
    try {
        Call(c, rt_module_entry);
        std::fprintf(stderr, "module entry returned %016" PRIx64 "\n", c.x[0]);
    } catch (const ThreadExit&) {
        std::fprintf(stderr, "main thread exited\n");
    }
    return 0;
}
