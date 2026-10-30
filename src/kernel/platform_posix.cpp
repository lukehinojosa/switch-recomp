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

} // namespace platform

} // namespace hk
