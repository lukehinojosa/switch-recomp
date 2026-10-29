// Native (authored) CMIF services for a module host: stubs for the services a
// recompiled module calls during start-up, served from one kernel process on
// one host thread. Each port gets a root interface per session; an interface
// can return sub-interfaces as moved sessions.
#pragma once

#include "hk/kernel.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace services {

// A buffer the request carries, readable and writable through the host's
// memory (the kernel has already mapped or copied it in).
struct BufferRef {
    uint64_t address{}, size{};
};

class Interface;

struct Request {
    uint32_t command{};
    uint64_t pid{};
    std::vector<std::byte> raw;             // input arguments after the CMIF header
    std::vector<uint32_t> copy, move;       // incoming handles
    std::vector<BufferRef> statics, sends, receives, exchanges;
    std::function<bool(uint64_t, std::span<std::byte>)> read;
    std::function<bool(uint64_t, std::span<const std::byte>)> write;
    // Creates shared memory with these contents; returns a handle to copy out.
    std::function<uint32_t(std::vector<std::byte>)> create_shared_memory;
    // Creates an event that is never signalled; returns its readable handle.
    std::function<uint32_t()> create_event;

    template <class T>
    T In(size_t offset) const {
        T value{};
        if (offset + sizeof(T) <= raw.size())
            std::memcpy(&value, raw.data() + offset, sizeof(T));
        return value;
    }
    // The bytes of the first of statics or sends that is non-empty (the
    // "auto select" buffers clients send as both).
    std::vector<std::byte> InBuffer(size_t index = 0) const;
    // Writes to the first non-empty of receives (B) at index.
    bool OutBuffer(std::span<const std::byte> bytes, size_t index = 0) const;
};

struct Response {
    std::vector<std::byte> raw;
    std::vector<uint32_t> copy;
    std::vector<std::shared_ptr<Interface>> objects; // returned as moved sessions

    template <class T>
    void Out(const T& value) {
        const auto* bytes = reinterpret_cast<const std::byte*>(&value);
        raw.insert(raw.end(), bytes, bytes + sizeof(T));
    }
};

class Interface {
public:
    virtual ~Interface() = default;
    virtual const char* Name() const = 0;
    // Returns the CMIF result. Unknown commands should return an error
    // rather than succeed silently.
    virtual hk::Result Handle(const Request& request, Response& response) = 0;
};

using Factory = std::function<std::shared_ptr<Interface>()>;

class NativeHost {
public:
    NativeHost(hk::Kernel& kernel, bool trace);
    ~NativeHost();
    NativeHost(const NativeHost&) = delete;
    NativeHost& operator=(const NativeHost&) = delete;

    // Publishes a port; call before Start.
    void Add(std::string name, uint32_t max_sessions, Factory factory);
    void Start();

    struct State;

private:
    std::unique_ptr<State> state_;
};

// Result codes in a module's own space.
constexpr hk::Result MakeResult(uint32_t module, uint32_t description) { return module | (description << 9); }

} // namespace services
