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

} // namespace platform

} // namespace hk
