#include "module_link.h"

#include "hk/link.h"
#include "hk/native.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef CreateProcess
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace client {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;
constexpr uint64_t kName = kBase + 0x200;
constexpr uint32_t kInMagic = 0x49434653, kOutMagic = 0x4F434653; // "SFCI", "SFCO"

#ifdef _WIN32
// Quotes one argument for CreateProcessW's command line.
std::wstring Quote(const std::wstring& argument) {
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : argument) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        out.append(c == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
        backslashes = 0;
        out.push_back(c);
    }
    out.append(backslashes * 2, L'\\');
    return out + L"\"";
}

std::wstring Widen(const std::string& text) {
    if (text.empty())
        return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

[[noreturn]] void Throw(const char* what) {
    throw std::runtime_error(std::string(what) + " (Windows error " + std::to_string(GetLastError()) + ")");
}
#else
[[noreturn]] void Throw(const char* what, int error = errno) {
    throw std::runtime_error(std::string(what) + " (" + std::strerror(error) + ")");
}
#endif

} // namespace

struct ModuleLink::State {
    std::mutex lock;
    FlatMemory memory{kBase, 0x1000};
    hk::Kernel kernel;
    std::shared_ptr<hk::Process> process;
    hk_thread* thread = nullptr;
#ifdef _WIN32
    HANDLE child = nullptr, job = nullptr;
#else
    pid_t child = 0;
    std::mutex reap;
    bool exited = false;
#endif

    ~State() {
        if (process)
            kernel.DestroyProcess(process);
#ifdef _WIN32
        if (child) {
            TerminateProcess(child, 1);
            WaitForSingleObject(child, INFINITE);
            CloseHandle(child);
        }
        if (job)
            CloseHandle(job);
#else
        if (child && !exited) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
        }
#endif
    }
};

namespace {

#ifdef _WIN32
// Starts the host with the link's pipes; returns the stream to it.
std::unique_ptr<hk::ByteStream> StartChild(ModuleLink::State& state, const ModuleOptions& options) {
    // to_child: we write, the child reads. from_child: the child writes.
    SECURITY_ATTRIBUTES inherit{sizeof inherit, nullptr, TRUE};
    HANDLE to_child_read, to_child_write, from_child_read, from_child_write;
    if (!CreatePipe(&to_child_read, &to_child_write, &inherit, 0))
        Throw("could not create a pipe");
    if (!CreatePipe(&from_child_read, &from_child_write, &inherit, 0)) {
        CloseHandle(to_child_read);
        CloseHandle(to_child_write);
        Throw("could not create a pipe");
    }
    SetHandleInformation(to_child_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(from_child_read, HANDLE_FLAG_INHERIT, 0);
    // The link owns our ends from here, including on failure below.
    auto stream = hk::OpenPipeStream(reinterpret_cast<uintptr_t>(from_child_read),
                                     reinterpret_cast<uintptr_t>(to_child_write));

    // Named exactly, rather than searched for from the command line, which
    // also accepts forward slashes in a relative path.
    const std::wstring executable = std::filesystem::absolute(options.executable).make_preferred().wstring();
    std::wstring command = Quote(executable) + L" --link " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(to_child_read)) + L" " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(from_child_write));
    for (const auto& argument : options.arguments)
        command += L" " + Quote(Widen(argument));

    // The child inherits the two pipe ends and our standard handles, nothing
    // else this process happens to have marked inheritable.
    std::vector<HANDLE> inherited{to_child_read, from_child_write};
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof startup;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    HANDLE* standard[] = {&startup.StartupInfo.hStdInput, &startup.StartupInfo.hStdOutput,
                          &startup.StartupInfo.hStdError};
    const DWORD ids[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (int i = 0; i < 3; ++i) {
        HANDLE handle = GetStdHandle(ids[i]);
        if (handle == INVALID_HANDLE_VALUE || !handle ||
            !SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            continue;
        *standard[i] = handle;
        if (std::find(inherited.begin(), inherited.end(), handle) == inherited.end())
            inherited.push_back(handle);
    }
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<std::byte> attributes(size);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size) ||
        !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
                                   inherited.size() * sizeof(HANDLE), nullptr, nullptr))
        Throw("could not prepare the child's inherited handles");

    // A job that kills the child when its last handle closes, which happens
    // when this process ends for any reason.
    state.job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!state.job || !SetInformationJobObject(state.job, JobObjectExtendedLimitInformation, &limits, sizeof limits))
        Throw("could not create a job for the child");

    PROCESS_INFORMATION info{};
    const BOOL started = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                        &startup.StartupInfo, &info);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    CloseHandle(to_child_read);
    CloseHandle(from_child_write);
    if (!started)
        Throw("could not start the module host");
    state.child = info.hProcess;
    if (!AssignProcessToJobObject(state.job, info.hProcess)) {
        CloseHandle(info.hThread);
        Throw("could not place the module host in its job");
    }
    ResumeThread(info.hThread);
    CloseHandle(info.hThread);
    return stream;
}
#else
std::unique_ptr<hk::ByteStream> StartChild(ModuleLink::State& state, const ModuleOptions& options) {
    // One socket pair per direction, so that a write to a child that has
    // gone fails instead of raising SIGPIPE. status reports a failed exec.
    int to_child[2], from_child[2], status[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, to_child))
        Throw("could not create a socket pair");
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, from_child)) {
        close(to_child[0]);
        close(to_child[1]);
        Throw("could not create a socket pair");
    }
    if (pipe2(status, O_CLOEXEC)) {
        for (int fd : {to_child[0], to_child[1], from_child[0], from_child[1]})
            close(fd);
        Throw("could not create a pipe");
    }
    // The link owns our ends from here, including on failure below.
    auto stream = hk::OpenPipeStream(static_cast<uintptr_t>(from_child[0]), static_cast<uintptr_t>(to_child[1]));

    const std::string executable = std::filesystem::absolute(options.executable).string();
    std::vector<std::string> arguments{executable, "--link", std::to_string(to_child[0]), std::to_string(from_child[1])};
    arguments.insert(arguments.end(), options.arguments.begin(), options.arguments.end());
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    argv.push_back(nullptr);

    const pid_t parent = getpid();
    const pid_t pid = fork();
    if (pid == 0) {
        // The child dies with this process, as a Windows job would see to.
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent)
            _exit(127);
        // Its two link ends survive the exec; everything else marked
        // close-on-exec does not.
        fcntl(to_child[0], F_SETFD, 0);
        fcntl(from_child[1], F_SETFD, 0);
        execv(argv[0], argv.data());
        const int error = errno;
        (void)!write(status[1], &error, sizeof error);
        _exit(127);
    }
    const int fork_error = errno;
    close(to_child[0]);
    close(from_child[1]);
    close(status[1]);
    if (pid < 0) {
        close(status[0]);
        Throw("could not start the module host", fork_error);
    }
    state.child = pid;
    int error = 0;
    const ssize_t got = read(status[0], &error, sizeof error);
    close(status[0]);
    if (got == sizeof error) {
        waitpid(pid, nullptr, 0);
        state.exited = true;
        Throw("could not start the module host", error);
    }
    return stream;
}
#endif

} // namespace

std::shared_ptr<ModuleLink> ModuleLink::Start(const ModuleOptions& options) {
    auto state = std::make_shared<State>();
    auto stream = StartChild(*state, options);
    state->process = state->kernel.CreateProcess(options.process_id, state->memory);
    state->thread = state->kernel.CreateThread(state->process, kTls);
    state->kernel.AttachLink(std::move(stream), true);
    return std::shared_ptr<ModuleLink>(new ModuleLink(std::move(state)));
}

ModuleLink::ModuleLink(std::shared_ptr<State> state) : state_(std::move(state)) {}

ModuleLink::~ModuleLink() = default;

std::shared_ptr<Session> ModuleLink::Connect(std::string_view port, std::chrono::milliseconds wait) {
    const auto deadline = std::chrono::steady_clock::now() + wait;
    for (;;) {
        hk::Result result;
        uint32_t handle = 0;
        {
            std::lock_guard guard(state_->lock);
            state_->memory.WriteString(kName, port);
            result = svc::ConnectToNamedPort(state_->thread, kName, handle);
        }
        if (result == hk::result::Success)
            return std::make_shared<Session>(state_, handle);
        if (result != hk::result::NotFound || !Running() || std::chrono::steady_clock::now() >= deadline)
            return nullptr;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

#ifdef _WIN32
bool ModuleLink::Running() const { return WaitForSingleObject(state_->child, 0) == WAIT_TIMEOUT; }
#else
bool ModuleLink::Running() const {
    std::lock_guard guard(state_->reap);
    if (!state_->exited && waitpid(state_->child, nullptr, WNOHANG) == state_->child)
        state_->exited = true;
    return !state_->exited;
}
#endif

Session::Session(std::shared_ptr<ModuleLink::State> link, uint32_t handle)
    : link_(std::move(link)), handle_(handle) {}

Session::~Session() {
    std::lock_guard guard(link_->lock);
    svc::CloseHandle(link_->thread, handle_);
}

Reply Session::Request(uint32_t command, std::span<const std::byte> raw, bool send_pid) {
    Message request;
    request.type = 4;
    request.send_pid = send_pid;
    // The CMIF header starts at the first 16-byte boundary after the HIPC
    // header; clients reserve 16 bytes for that alignment whatever part of it
    // is used, and servers check the data size against it.
    const uint32_t data_word = 2 + (send_pid ? 3 : 0);
    const uint32_t pad = (4 - data_word % 4) % 4;
    request.data.assign(pad, 0);
    request.data.insert(request.data.end(), {kInMagic, 0, command, 0});
    std::vector<uint32_t> words((raw.size() + 3) / 4);
    if (!raw.empty())
        std::memcpy(words.data(), raw.data(), raw.size());
    request.data.insert(request.data.end(), words.begin(), words.end());
    request.data.insert(request.data.end(), 4 - pad, 0);

    Reply reply;
    Message message;
    {
        std::lock_guard guard(link_->lock);
        WriteMessage(link_->memory, kTls, request);
        reply.kernel = svc::SendSyncRequest(link_->thread, handle_);
        if (reply.kernel)
            return reply;
        message = ReadMessage(link_->memory, kTls);
        for (uint32_t handle : message.copy) {
            if (auto event = Event::Adopt(link_, handle)) {
                reply.events.push_back(std::move(event));
            } else {
                svc::CloseHandle(link_->thread, handle);
                ++reply.copied_handles;
            }
        }
    }
    for (uint32_t handle : message.move) {
        if (auto event = Event::Adopt(link_, handle))
            reply.events.push_back(std::move(event));
        else
            reply.objects.push_back(std::make_shared<Session>(link_, handle));
    }
    const uint32_t reply_word = 2 + (message.move.empty() && message.copy.empty() ? 0 : 1) +
                                static_cast<uint32_t>(message.move.size() + message.copy.size());
    const size_t reply_pad = (4 - reply_word % 4) % 4;
    if (message.data.size() < reply_pad + 4 || message.data[reply_pad] != kOutMagic) {
        reply.malformed = true;
        return reply;
    }
    reply.result = message.data[reply_pad + 2];
    // The words after the output follow the 16 bytes of alignment space; a
    // reply's data size counts them, so drop the unused part at the end.
    const size_t first = reply_pad + 4;
    const size_t end = message.data.size() - std::min(message.data.size() - first, size_t{4} - reply_pad);
    for (size_t i = first; i < end; ++i) {
        const auto* bytes = reinterpret_cast<const std::byte*>(&message.data[i]);
        reply.raw.insert(reply.raw.end(), bytes, bytes + 4);
    }
    return reply;
}

struct EventMirror {
    std::mutex lock;
    std::condition_variable changed;
    bool signaled = false;
    std::function<void(bool)> on_change;
    uint64_t watch = 0;
};

std::shared_ptr<Event> Event::Adopt(const std::shared_ptr<ModuleLink::State>& link, uint32_t handle) {
    auto mirror = std::make_shared<EventMirror>();
    // The kernel keeps this callback, and with it the mirror, until Unwatch.
    mirror->watch = link->kernel.WatchEvent(link->process, handle, [mirror](bool signaled) {
        std::function<void(bool)> notify;
        {
            std::lock_guard guard(mirror->lock);
            mirror->signaled = signaled;
            notify = mirror->on_change;
        }
        mirror->changed.notify_all();
        if (notify)
            notify(signaled);
    });
    if (!mirror->watch)
        return nullptr;
    return std::make_shared<Event>(link, handle, std::move(mirror));
}

Event::Event(std::shared_ptr<ModuleLink::State> link, uint32_t handle, std::shared_ptr<EventMirror> mirror)
    : link_(std::move(link)), handle_(handle), mirror_(std::move(mirror)) {}

Event::~Event() {
    link_->kernel.Unwatch(mirror_->watch);
    std::lock_guard guard(link_->lock);
    svc::CloseHandle(link_->thread, handle_);
}

bool Event::Signaled() const {
    std::lock_guard guard(mirror_->lock);
    return mirror_->signaled;
}

bool Event::Wait(std::chrono::nanoseconds timeout) {
    std::unique_lock guard(mirror_->lock);
    const auto signaled = [&] { return mirror_->signaled; };
    if (timeout.count() < 0) {
        mirror_->changed.wait(guard, signaled);
        return true;
    }
    return mirror_->changed.wait_for(guard, timeout, signaled);
}

void Event::Clear() {
    std::lock_guard guard(link_->lock);
    svc::ClearEvent(link_->thread, handle_);
}

void Event::Watch(std::function<void(bool)> on_change) {
    std::lock_guard guard(mirror_->lock);
    mirror_->on_change = std::move(on_change);
}

} // namespace client
