// A test's child process joined to it by a link: started as
// <program> <read> <write>, the two handles being the child's ends.
#pragma once

#include "hk/link.h"

#include <cstdint>
#include <filesystem>
#include <memory>

namespace testing {

// A program next to the running test's executable, by its name without an
// extension.
std::filesystem::path Beside(const char* name);

// Two ends of a link inside this process, for joining two kernels in it.
struct StreamPair {
    std::unique_ptr<hk::ByteStream> first, second;
};
StreamPair OpenStreamPair();

class LinkedChild {
public:
    LinkedChild() = default;
    ~LinkedChild(); // kills the child if it is still running
    LinkedChild(const LinkedChild&) = delete;
    LinkedChild& operator=(const LinkedChild&) = delete;

    // Starts program; false if it could not be.
    bool Start(const std::filesystem::path& program);
    // This side of the link, once.
    std::unique_ptr<hk::ByteStream> TakeStream() { return std::move(stream_); }
    // Waits for the child to exit; false on timeout.
    bool Wait(int timeout_ms, int& exit_code);
    void Kill(int exit_code);
    bool Started() const { return process_ != 0; }

private:
    std::unique_ptr<hk::ByteStream> stream_;
    intptr_t process_ = 0; // a HANDLE, or a pid
    bool reaped_ = false;
    int exit_code_ = 0; // once reaped
};

} // namespace testing
