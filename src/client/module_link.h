// The client side of a module host, for a title process: starts module_host
// (or any host that takes --link) as a child process joined by a link, and
// sends CMIF requests to the ports the module registers.
//
// The client is one guest process in its own kernel, with one thread whose
// message buffer every request uses; requests from different host threads
// are serialized. A child that exits closes every session, and later
// requests fail with a kernel result. The child is killed when the link is
// destroyed or this process ends.
#pragma once

#include "hk/kernel.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace client {

struct ModuleOptions {
    std::filesystem::path executable; // module_host.exe
    // Arguments after --link <read> <write>, such as the module's ELF.
    std::vector<std::string> arguments;
    // This client's process ID as the module sees it in PID descriptors.
    uint64_t process_id = 0;
};

class Session;

struct Reply {
    // The SendSyncRequest result; anything but success means the session or
    // the link failed and there is no reply.
    hk::Result kernel = 0;
    hk::Result result = 0;       // the CMIF result
    std::vector<std::byte> raw;  // output after the CMIF header, in whole words
    std::vector<std::shared_ptr<Session>> objects; // sessions the reply moved
    size_t copied_handles = 0;   // copied handles, which are closed unused
    bool malformed = false;      // the reply had no CMIF output header
};

class ModuleLink {
public:
    // Throws std::runtime_error if the child cannot be started.
    static std::shared_ptr<ModuleLink> Start(const ModuleOptions& options);
    ~ModuleLink();
    ModuleLink(const ModuleLink&) = delete;
    ModuleLink& operator=(const ModuleLink&) = delete;

    // Connects to a port the module registers, waiting up to wait for it to
    // appear. Null if it does not, or the connection fails.
    std::shared_ptr<Session> Connect(std::string_view port, std::chrono::milliseconds wait);
    // Whether the child is still running.
    bool Running() const;

    struct State;

private:
    explicit ModuleLink(std::shared_ptr<State> state);
    std::shared_ptr<State> state_;
};

// A client session to the module: a port connection or a sub-interface.
class Session {
public:
    Session(std::shared_ptr<ModuleLink::State> link, uint32_t handle);
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // One CMIF request without buffers or handles. raw is the input after the
    // CMIF header; with send_pid the kernel supplies this client's process ID.
    Reply Request(uint32_t command, std::span<const std::byte> raw, bool send_pid);

private:
    std::shared_ptr<ModuleLink::State> link_;
    uint32_t handle_;
};

} // namespace client
