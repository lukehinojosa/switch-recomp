// Host-platform pieces the kernel needs for links.
#pragma once

#include <atomic>
#include <functional>
#include <thread>

namespace hk::platform {

// A thread whose blocking I/O can be cancelled. Stop cancels any read or
// write the body is blocked in, waits for the body to return and joins.
class BlockingThread {
public:
    BlockingThread() = default;
    BlockingThread(const BlockingThread&) = delete;
    BlockingThread& operator=(const BlockingThread&) = delete;
    ~BlockingThread() { Stop(); }

    void Start(std::function<void()> body);
    void Stop();

private:
    std::thread thread_;
    std::atomic<void*> native_{};
    std::atomic<bool> done_{};
    std::atomic<bool> cancel_{}; // POSIX: an interrupted read or write gives up
};

} // namespace hk::platform
