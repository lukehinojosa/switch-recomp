// Host-platform pieces the kernel needs for links.
#pragma once

#include "hk/link.h"

#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace hk::platform {

// A host process joined to this one by a link: started as executable --link
// <read> <write> followed by arguments, the two handles being its ends. It
// is killed when this object is destroyed or this process ends (a job on
// Windows, PR_SET_PDEATHSIG on Linux).
class LinkedProcess {
public:
    // Throws std::runtime_error if the process cannot be started.
    LinkedProcess(const std::filesystem::path& executable, const std::vector<std::string>& arguments);
    ~LinkedProcess();
    LinkedProcess(const LinkedProcess&) = delete;
    LinkedProcess& operator=(const LinkedProcess&) = delete;

    // This side of the link, once.
    std::unique_ptr<ByteStream> TakeStream() { return std::move(stream_); }
    bool Running();

private:
    std::unique_ptr<ByteStream> stream_;
#ifdef _WIN32
    void Release(); // kills the process and closes both handles

    void* process_ = nullptr; // HANDLEs
    void* job_ = nullptr;
#else
    int process_ = 0;
    std::mutex reap_;
    bool exited_ = false;
#endif
};

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
