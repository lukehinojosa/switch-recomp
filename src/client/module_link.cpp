#include "module_link.h"

#include "hk/link.h"
#include "hk/native.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef CreateProcess

#include <algorithm>
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

} // namespace

struct ModuleLink::State {
    std::mutex lock;
    FlatMemory memory{kBase, 0x1000};
    hk::Kernel kernel;
    std::shared_ptr<hk::Process> process;
    hk_thread* thread = nullptr;
    HANDLE child = nullptr, job = nullptr;

    ~State() {
        if (process)
            kernel.DestroyProcess(process);
        if (child) {
            TerminateProcess(child, 1);
            WaitForSingleObject(child, INFINITE);
            CloseHandle(child);
        }
        if (job)
            CloseHandle(job);
    }
};

std::shared_ptr<ModuleLink> ModuleLink::Start(const ModuleOptions& options) {
    auto state = std::make_shared<State>();

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
    state->job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!state->job || !SetInformationJobObject(state->job, JobObjectExtendedLimitInformation, &limits, sizeof limits))
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
    state->child = info.hProcess;
    if (!AssignProcessToJobObject(state->job, info.hProcess)) {
        CloseHandle(info.hThread);
        Throw("could not place the module host in its job");
    }
    ResumeThread(info.hThread);
    CloseHandle(info.hThread);

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

bool ModuleLink::Running() const { return WaitForSingleObject(state_->child, 0) == WAIT_TIMEOUT; }

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
        for (uint32_t handle : message.copy)
            svc::CloseHandle(link_->thread, handle);
    }
    reply.copied_handles = message.copy.size();
    for (uint32_t handle : message.move)
        reply.objects.push_back(std::make_shared<Session>(link_, handle));
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

} // namespace client
