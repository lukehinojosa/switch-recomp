#include "hk/link.h"
#include "platform.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace hk {

namespace {

class PipeStream final : public ByteStream {
public:
    PipeStream(HANDLE read, HANDLE write) : read_(read), write_(write) {}
    ~PipeStream() override {
        CloseHandle(read_);
        CloseHandle(write_);
    }

    bool Read(std::span<std::byte> out) override {
        while (!out.empty()) {
            DWORD transferred = 0;
            const DWORD request = static_cast<DWORD>(std::min<size_t>(out.size(), 1u << 20));
            if (!ReadFile(read_, out.data(), request, &transferred, nullptr) || transferred == 0)
                return false;
            out = out.subspan(transferred);
        }
        return true;
    }

    bool Write(std::span<const std::byte> in) override {
        while (!in.empty()) {
            DWORD transferred = 0;
            const DWORD request = static_cast<DWORD>(std::min<size_t>(in.size(), 1u << 20));
            if (!WriteFile(write_, in.data(), request, &transferred, nullptr) || transferred == 0)
                return false;
            in = in.subspan(transferred);
        }
        return true;
    }

private:
    HANDLE read_, write_;
};

} // namespace

std::unique_ptr<ByteStream> OpenPipeStream(uintptr_t read_handle, uintptr_t write_handle) {
    return std::make_unique<PipeStream>(reinterpret_cast<HANDLE>(read_handle), reinterpret_cast<HANDLE>(write_handle));
}

namespace platform {

void BlockingThread::Start(std::function<void()> body) {
    thread_ = std::thread([this, body = std::move(body)] {
        HANDLE self = nullptr;
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &self, 0, FALSE,
                        DUPLICATE_SAME_ACCESS);
        native_ = self;
        body();
        done_ = true;
    });
}

void BlockingThread::Stop() {
    if (!thread_.joinable())
        return;
    // A cancel can land before the body blocks, so repeat until it returns.
    while (!done_) {
        if (void* native = native_.load())
            CancelSynchronousIo(static_cast<HANDLE>(native));
        Sleep(1);
    }
    thread_.join();
    if (void* native = native_.exchange(nullptr))
        CloseHandle(static_cast<HANDLE>(native));
}

namespace {

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

LinkedProcess::LinkedProcess(const std::filesystem::path& executable_path, const std::vector<std::string>& arguments) {
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
    stream_ = OpenPipeStream(reinterpret_cast<uintptr_t>(from_child_read), reinterpret_cast<uintptr_t>(to_child_write));

    // Named exactly, rather than searched for from the command line, which
    // also accepts forward slashes in a relative path.
    const std::wstring executable = std::filesystem::absolute(executable_path).make_preferred().wstring();
    std::wstring command = Quote(executable) + L" --link " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(to_child_read)) + L" " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(from_child_write));
    for (const auto& argument : arguments)
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
    job_ = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job_ || !SetInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof limits)) {
        const DWORD error = GetLastError();
        Release();
        SetLastError(error);
        Throw("could not create a job for the child");
    }

    PROCESS_INFORMATION info{};
    const BOOL started = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                        &startup.StartupInfo, &info);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    CloseHandle(to_child_read);
    CloseHandle(from_child_write);
    if (!started)
        Throw("could not start the module host");
    process_ = info.hProcess;
    if (!AssignProcessToJobObject(job_, info.hProcess)) {
        const DWORD error = GetLastError();
        CloseHandle(info.hThread);
        Release();
        SetLastError(error);
        Throw("could not place the module host in its job");
    }
    ResumeThread(info.hThread);
    CloseHandle(info.hThread);
}

LinkedProcess::~LinkedProcess() { Release(); }

void LinkedProcess::Release() {
    if (process_) {
        TerminateProcess(process_, 1);
        WaitForSingleObject(process_, INFINITE);
        CloseHandle(process_);
        process_ = nullptr;
    }
    if (job_) {
        CloseHandle(job_);
        job_ = nullptr;
    }
}

bool LinkedProcess::Running() { return WaitForSingleObject(process_, 0) == WAIT_TIMEOUT; }

} // namespace platform

} // namespace hk
