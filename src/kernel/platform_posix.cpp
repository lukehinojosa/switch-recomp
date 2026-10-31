#include "hk/link.h"
#include "platform.h"

#include <cerrno>
#include <csignal>
#include <mutex>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <vector>

namespace hk {

namespace platform {

namespace {

// Set on a BlockingThread's own thread: a read or write interrupted while it
// is set gives up instead of retrying.
thread_local std::atomic<bool>* t_cancel = nullptr;

// The signal that interrupts a blocked read or write. Its handler does
// nothing; installed without SA_RESTART, so the call returns EINTR.
constexpr int kWakeSignal = SIGURG;

void InstallWakeHandler() {
    static std::once_flag once;
    std::call_once(once, [] {
        struct sigaction action{};
        action.sa_handler = [](int) {};
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(kWakeSignal, &action, nullptr);
    });
}

} // namespace

bool Cancelled() { return t_cancel && t_cancel->load(); }

} // namespace platform

namespace {

class PipeStream final : public ByteStream {
public:
    PipeStream(int read, int write) : read_(read), write_(write) {}
    ~PipeStream() override {
        close(read_);
        close(write_);
    }

    bool Read(std::span<std::byte> out) override {
        while (!out.empty()) {
            const ssize_t n = read(read_, out.data(), std::min<size_t>(out.size(), 1u << 20));
            if (n < 0 && errno == EINTR && !platform::Cancelled())
                continue;
            if (n <= 0)
                return false;
            out = out.subspan(static_cast<size_t>(n));
        }
        return true;
    }

    bool Write(std::span<const std::byte> in) override {
        while (!in.empty()) {
            const size_t request = std::min<size_t>(in.size(), 1u << 20);
            // A socket's peer may be gone: fail the write rather than raise SIGPIPE.
            ssize_t n = send(write_, in.data(), request, MSG_NOSIGNAL);
            if (n < 0 && errno == ENOTSOCK)
                n = write(write_, in.data(), request);
            if (n < 0 && errno == EINTR && !platform::Cancelled())
                continue;
            if (n <= 0)
                return false;
            in = in.subspan(static_cast<size_t>(n));
        }
        return true;
    }

private:
    int read_, write_;
};

} // namespace

std::unique_ptr<ByteStream> OpenPipeStream(uintptr_t read_handle, uintptr_t write_handle) {
    return std::make_unique<PipeStream>(static_cast<int>(read_handle), static_cast<int>(write_handle));
}

namespace platform {

void BlockingThread::Start(std::function<void()> body) {
    InstallWakeHandler();
    thread_ = std::thread([this, body = std::move(body)] {
        t_cancel = &cancel_;
        native_ = reinterpret_cast<void*>(1); // running: Stop may signal it
        body();
        done_ = true;
    });
}

void BlockingThread::Stop() {
    if (!thread_.joinable())
        return;
    cancel_ = true;
    // A signal can land before the body blocks, so repeat until it returns.
    while (!done_) {
        if (native_.load())
            pthread_kill(thread_.native_handle(), kWakeSignal);
        sched_yield();
        usleep(1000);
    }
    thread_.join();
    native_ = nullptr;
}

namespace {

[[noreturn]] void Throw(const char* what, int error = errno) {
    throw std::runtime_error(std::string(what) + " (" + std::strerror(error) + ")");
}

} // namespace

LinkedProcess::LinkedProcess(const std::filesystem::path& executable_path, const std::vector<std::string>& arguments) {
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
    stream_ = OpenPipeStream(static_cast<uintptr_t>(from_child[0]), static_cast<uintptr_t>(to_child[1]));

    const std::string executable = std::filesystem::absolute(executable_path).string();
    std::vector<std::string> command{executable, "--link", std::to_string(to_child[0]), std::to_string(from_child[1])};
    command.insert(command.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    for (auto& argument : command)
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
    process_ = pid;
    int error = 0;
    const ssize_t got = read(status[0], &error, sizeof error);
    close(status[0]);
    if (got == sizeof error) {
        waitpid(pid, nullptr, 0);
        exited_ = true;
        Throw("could not start the module host", error);
    }
}

LinkedProcess::~LinkedProcess() {
    if (process_ && !exited_) {
        kill(process_, SIGKILL);
        waitpid(process_, nullptr, 0);
    }
}

bool LinkedProcess::Running() {
    std::lock_guard guard(reap_);
    if (!exited_ && waitpid(process_, nullptr, WNOHANG) == process_)
        exited_ = true;
    return !exited_;
}

} // namespace platform

} // namespace hk
