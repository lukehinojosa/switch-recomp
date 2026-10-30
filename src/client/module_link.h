// The client side of a module host, for a title process: starts module_host
// (or any host that takes --link) as a child process joined by a link, and
// sends CMIF requests to the ports the module registers. On Windows the link
// is two pipes and a job kills the child; elsewhere two socket pairs, and the
// child gets PR_SET_PDEATHSIG (Linux).
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
#include <functional>
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
class Event;
struct EventMirror;

struct Reply {
    // The SendSyncRequest result; anything but success means the session or
    // the link failed and there is no reply.
    hk::Result kernel = 0;
    hk::Result result = 0;       // the CMIF result
    std::vector<std::byte> raw;  // output after the CMIF header, in whole words
    std::vector<std::shared_ptr<Session>> objects; // sessions the reply moved
    std::vector<std::shared_ptr<Event>> events;    // readable events it copied or moved
    size_t copied_handles = 0;   // other copied handles, which are closed unused
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

// A readable event from the module: a mirror of the module's own event, kept
// current over the link. Signalled only by the module; the title may wait on
// it and clear it, as a game does with an event a service returns.
class Event {
public:
    // Takes over handle, a readable event in the client's process. Null if it
    // is not one.
    static std::shared_ptr<Event> Adopt(const std::shared_ptr<ModuleLink::State>& link, uint32_t handle);
    Event(std::shared_ptr<ModuleLink::State> link, uint32_t handle, std::shared_ptr<EventMirror> mirror);
    ~Event();
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;

    bool Signaled() const;
    // Waits until signalled or the timeout passes (negative: no timeout).
    // True if signalled.
    bool Wait(std::chrono::nanoseconds timeout);
    void Clear();
    // Calls on_change with the new state after every change (not now), on the
    // link's thread. It must not call into the client; a title passes the
    // state on to its own kernel's event. Replaces any earlier callback.
    void Watch(std::function<void(bool)> on_change);

private:
    std::shared_ptr<ModuleLink::State> link_;
    uint32_t handle_;
    std::shared_ptr<EventMirror> mirror_;
};

} // namespace client
