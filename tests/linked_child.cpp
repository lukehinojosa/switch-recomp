#include "linked_child.h"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace testing {

#ifdef _WIN32

std::filesystem::path Beside(const char* name) {
    wchar_t path[MAX_PATH];
    const DWORD size = GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::filesystem::path(std::wstring(path, size)).parent_path() / (std::string(name) + ".exe");
}

bool LinkedChild::Start(const std::filesystem::path& program) {
    // to_child: we write, the child reads. from_child: the child writes.
    SECURITY_ATTRIBUTES inherit{sizeof inherit, nullptr, TRUE};
    HANDLE to_child_read, to_child_write, from_child_read, from_child_write;
    if (!CreatePipe(&to_child_read, &to_child_write, &inherit, 0))
        return false;
    if (!CreatePipe(&from_child_read, &from_child_write, &inherit, 0)) {
        CloseHandle(to_child_read);
        CloseHandle(to_child_write);
        return false;
    }
    SetHandleInformation(to_child_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(from_child_read, HANDLE_FLAG_INHERIT, 0);
    stream_ = hk::OpenPipeStream(reinterpret_cast<uintptr_t>(from_child_read),
                                 reinterpret_cast<uintptr_t>(to_child_write));
    std::wstring command = L"\"" + program.wstring() + L"\" " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(to_child_read)) + L" " +
                           std::to_wstring(reinterpret_cast<uintptr_t>(from_child_write));
    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    PROCESS_INFORMATION info{};
    const bool started =
        CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &info);
    CloseHandle(to_child_read);
    CloseHandle(from_child_write);
    if (!started)
        return false;
    CloseHandle(info.hThread);
    process_ = reinterpret_cast<intptr_t>(info.hProcess);
    return true;
}

bool LinkedChild::Wait(int timeout_ms, int& exit_code) {
    const HANDLE process = reinterpret_cast<HANDLE>(process_);
    if (WaitForSingleObject(process, static_cast<DWORD>(timeout_ms)) != WAIT_OBJECT_0)
        return false;
    DWORD code = 0;
    GetExitCodeProcess(process, &code);
    exit_code = static_cast<int>(code);
    reaped_ = true;
    return true;
}

void LinkedChild::Kill(int exit_code) {
    if (process_ && !reaped_)
        TerminateProcess(reinterpret_cast<HANDLE>(process_), static_cast<UINT>(exit_code));
}

LinkedChild::~LinkedChild() {
    Kill(1);
    if (process_)
        CloseHandle(reinterpret_cast<HANDLE>(process_));
}

#else

std::filesystem::path Beside(const char* name) {
    return std::filesystem::read_symlink("/proc/self/exe").parent_path() / name;
}

bool LinkedChild::Start(const std::filesystem::path& program) {
    // One socket pair per direction, as module_client uses.
    int to_child[2], from_child[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, to_child))
        return false;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, from_child)) {
        close(to_child[0]);
        close(to_child[1]);
        return false;
    }
    stream_ = hk::OpenPipeStream(static_cast<uintptr_t>(from_child[0]), static_cast<uintptr_t>(to_child[1]));
    std::vector<std::string> arguments{program.string(), std::to_string(to_child[0]), std::to_string(from_child[1])};
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    argv.push_back(nullptr);
    const pid_t pid = fork();
    if (pid == 0) {
        fcntl(to_child[0], F_SETFD, 0);
        fcntl(from_child[1], F_SETFD, 0);
        execv(argv[0], argv.data());
        _exit(127);
    }
    close(to_child[0]);
    close(from_child[1]);
    if (pid < 0)
        return false;
    process_ = pid;
    return true;
}

bool LinkedChild::Wait(int timeout_ms, int& exit_code) {
    // A reaped pid is gone (and may be reused): answer from what was kept.
    if (reaped_) {
        exit_code = exit_code_;
        return true;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        int status = 0;
        if (waitpid(static_cast<pid_t>(process_), &status, WNOHANG) == process_) {
            reaped_ = true;
            exit_code = exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void LinkedChild::Kill(int) {
    if (process_ && !reaped_) {
        kill(static_cast<pid_t>(process_), SIGKILL);
        int ignored;
        Wait(10000, ignored);
    }
}

LinkedChild::~LinkedChild() { Kill(1); }

#endif

} // namespace testing
