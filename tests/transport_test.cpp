// Cross-process IPC tests: the echo server runs in a separate host process
// (echo_host) with its own kernel, reached over a pipe link. Each test runs
// twice: directly, and relayed through a third kernel between the client's
// and the host's, as a parent host joins two sysmodule hosts.
#include "echo_server.h"
#include "hk/link.h"
#include "linked_child.h"

#include <chrono>
#include <memory>
#include <cstdio>
#include <string>
#include <thread>

using namespace hk::result;

namespace {

int failures = 0;

#define CHECK(condition)                                                                     \
    do {                                                                                     \
        if (!(condition)) {                                                                  \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                                      \
        }                                                                                    \
    } while (0)

constexpr uint64_t ClientBase = 0x20000000, ClientPid = 0x7c;

bool relayed = false; // the second pass

struct World {
    static constexpr uint64_t ClientTls = ClientBase, ClientScratch = ClientBase + 0x200;

    World() {
        client = kernel.CreateProcess(ClientPid, client_memory);
        client_thread = kernel.CreateThread(client, ClientTls);

        CHECK(host.Start(testing::Beside("echo_host")));
        if (relayed) {
            hub = std::make_unique<hk::Kernel>();
            if (auto stream = host.TakeStream())
                hub->AttachLink(std::move(stream), true);
            auto pair = testing::OpenStreamPair();
            CHECK(pair.first && pair.second);
            if (pair.first && pair.second) {
                kernel.AttachLink(std::move(pair.first), true);
                hub->AttachLink(std::move(pair.second), false);
            }
        } else if (auto stream = host.TakeStream()) {
            kernel.AttachLink(std::move(stream), true);
        }
        session = Connect("echo");
    }
    ~World() {
        Stop();
        kernel.DestroyProcess(client);
    }

    hk::Result TryConnect(const char* name, uint32_t& handle) {
        client_memory.WriteString(ClientScratch, name);
        return svc::ConnectToNamedPort(client_thread, ClientScratch, handle);
    }
    // The host announces its port asynchronously, so retry until it exists.
    uint32_t Connect(const char* name) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        uint32_t handle = 0;
        hk::Result r;
        while ((r = TryConnect(name, handle)) == NotFound && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK(r == Success);
        return handle;
    }
    hk::Result Call(uint32_t handle, const Message& request, Message& reply) {
        WriteMessage(client_memory, ClientTls, request);
        const auto r = svc::SendSyncRequest(client_thread, handle);
        if (r == Success)
            reply = ReadMessage(client_memory, ClientTls);
        return r;
    }
    bool Echoes(uint32_t handle, std::vector<uint32_t> data) {
        data.insert(data.begin(), echo::Echo);
        Message request, reply;
        request.data = data;
        return Call(handle, request, reply) == Success && reply.data == data;
    }
    uint32_t ServerHandles() {
        Message request, reply;
        request.data = {echo::Stats};
        CHECK(Call(session, request, reply) == Success);
        return reply.data.empty() ? 0 : reply.data[0];
    }
    bool ServerHandlesBecome(uint32_t count) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (ServerHandles() != count) {
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }
    // Asks the host to quit and checks that it exits cleanly.
    void Stop() {
        if (!host.Started() || stopped)
            return;
        stopped = true;
        Message request, reply;
        request.data = {echo::Quit};
        CHECK(Call(session, request, reply) == Success);
        int code = 1;
        CHECK(host.Wait(10000, code));
        CHECK(code == 0);
    }

    std::unique_ptr<hk::Kernel> hub; // when relayed; destroyed after kernel
    hk::Kernel kernel;
    FlatMemory client_memory{ClientBase, 0x1000};
    std::shared_ptr<hk::Process> client;
    hk_thread* client_thread{};
    testing::LinkedChild host;
    bool stopped = false;
    uint32_t session{};
};

void EchoAcrossProcesses() {
    World world;
    CHECK(world.Echoes(world.session, {0xdeadbeef, 42, 7}));
    for (uint32_t i = 0; i < 1000; ++i)
        if (!world.Echoes(world.session, {i})) {
            CHECK(false);
            break;
        }
}

void PidCrossesTheLink() {
    World world;
    Message request, reply;
    request.send_pid = true;
    request.pid = 0x1234;
    request.data = {echo::WhoAmI};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(reply.data == (std::vector<uint32_t>{static_cast<uint32_t>(ClientPid), 0}));
}

void SubInterfaceMovesAcrossTheLink() {
    World world;
    const size_t before = world.kernel.HandleCount(world.client);
    Message request, reply;
    request.data = {echo::OpenSub};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(reply.move.size() == 1);
    CHECK(world.kernel.HandleCount(world.client) == before + 1);
    if (reply.move.size() == 1) {
        CHECK(world.Echoes(reply.move[0], {9, 8}));
        CHECK(svc::CloseHandle(world.client_thread, reply.move[0]) == Success);
    }
}

void ServerSessionMovesAcrossTheLink() {
    if (relayed)
        return; // a server end does not pass through a relay
    World world;
    uint32_t server_end, client_end;
    CHECK(svc::CreateSession(world.client_thread, server_end, client_end) == Success);
    Message request, reply;
    request.move = {server_end};
    request.data = {echo::Adopt};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(svc::CloseHandle(world.client_thread, server_end) == InvalidHandle);
    CHECK(world.Echoes(client_end, {5})); // a local client, served in the other process
}

void CopiedHandleCrossesAndStays() {
    World world;
    const uint32_t before = world.ServerHandles();
    uint32_t server_end, client_end;
    CHECK(svc::CreateSession(world.client_thread, server_end, client_end) == Success);
    Message request, reply;
    request.copy = {client_end};
    request.data = {echo::Echo};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(world.ServerHandles() == before + 1);
    CHECK(svc::CloseHandle(world.client_thread, client_end) == Success);
}

// A session the host serves, sent back to it: copied, the client keeps its
// own; moved, the host holds the only one, and either way it still works.
void SessionGoesBackToItsServer() {
    World world;
    Message request, reply;
    request.data = {echo::OpenSub};
    CHECK(world.Call(world.session, request, reply) == Success && reply.move.size() == 1);
    if (reply.move.size() != 1)
        return;
    const uint32_t sub = reply.move[0];
    const uint32_t before = world.ServerHandles();
    Message copy;
    copy.copy = {sub};
    copy.data = {echo::Echo};
    CHECK(world.Call(world.session, copy, reply) == Success);
    CHECK(world.ServerHandles() == before + 1);
    CHECK(world.Echoes(sub, {6}));
    Message move;
    move.move = {sub};
    move.data = {echo::Echo};
    CHECK(world.Call(world.session, move, reply) == Success);
    CHECK(world.ServerHandles() == before + 2);
    CHECK(svc::CloseHandle(world.client_thread, sub) == InvalidHandle);
}

// The server's event, copied to the client: a mirror the server's signals
// and clears reach before the reply that follows them.
uint32_t GetServerEvent(World& world) {
    Message request, reply;
    request.data = {echo::GetEvent};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(reply.copy.size() == 1);
    return reply.copy.empty() ? 0 : reply.copy[0];
}

void Command(World& world, uint32_t command, std::vector<uint32_t>* data = nullptr) {
    Message request, reply;
    request.data = {command};
    CHECK(world.Call(world.session, request, reply) == Success);
    if (data)
        *data = reply.data;
}

bool ClientSees(World& world, uint32_t event, int64_t timeout_ns = 0) {
    const uint32_t list[] = {event};
    world.client_memory.WriteWords(World::ClientScratch + 0x10, list);
    uint32_t index;
    return svc::WaitSynchronization(world.client_thread, World::ClientScratch + 0x10, 1, timeout_ns, index) == Success;
}

void EventSignalCrossesTheLink() {
    World world;
    const size_t before = world.kernel.HandleCount(world.client);
    const uint32_t event = GetServerEvent(world);
    CHECK(world.kernel.HandleCount(world.client) == before + 1);
    CHECK(!ClientSees(world, event));
    Command(world, echo::SignalIt);
    CHECK(ClientSees(world, event)); // the change arrived before the reply
    Command(world, echo::ClearIt);
    CHECK(!ClientSees(world, event));
    CHECK(svc::CloseHandle(world.client_thread, event) == Success);
    CHECK(world.kernel.HandleCount(world.client) == before);
}

void EventClearCrossesBack() {
    World world;
    const uint32_t event = GetServerEvent(world);
    Command(world, echo::SignalIt);
    CHECK(ClientSees(world, event));
    CHECK(svc::ClearEvent(world.client_thread, event) == Success);
    CHECK(!ClientSees(world, event));
    std::vector<uint32_t> seen;
    Command(world, echo::IsSignaled, &seen); // the clear arrived before the request
    CHECK(seen == std::vector<uint32_t>{0});
    Command(world, echo::SignalIt);
    CHECK(svc::ResetSignal(world.client_thread, event) == Success);
    Command(world, echo::IsSignaled, &seen);
    CHECK(seen == std::vector<uint32_t>{0});
    CHECK(svc::ResetSignal(world.client_thread, event) == InvalidState);
}

void WaitOnMirrorWakesOnSignal() {
    World world;
    const uint32_t event = GetServerEvent(world);
    constexpr uint64_t WaiterTls = ClientBase + 0xe00, WaiterList = ClientBase + 0xf00;
    hk_thread* waiter = world.kernel.CreateThread(world.client, WaiterTls);
    hk::Result waited = TimedOut;
    std::thread thread([&] {
        const uint32_t list[] = {event};
        world.client_memory.WriteWords(WaiterList, list);
        uint32_t index;
        waited = svc::WaitSynchronization(waiter, WaiterList, 1, -1, index);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Command(world, echo::SignalIt);
    thread.join();
    CHECK(waited == Success);
    world.kernel.DestroyThread(waiter);
}

void MirrorIsWatched() {
    World world;
    const uint32_t event = GetServerEvent(world);
    std::vector<bool> states;
    const uint64_t token = world.kernel.WatchEvent(world.client, event, [&](bool signaled) { states.push_back(signaled); });
    CHECK(token != 0);
    Command(world, echo::SignalIt);
    Command(world, echo::ClearIt);
    world.kernel.Unwatch(token);
    Command(world, echo::SignalIt);
    CHECK(states == (std::vector<bool>{false, true, false}));
    CHECK(world.kernel.WatchEvent(world.client, world.session, [](bool) {}) == 0);
}

// Client-side layout for the Buffers command, in the client's scratch area.
struct BufferCase {
    static constexpr uint64_t X = 0x400, A = 0x500, B = 0x600, W = 0x700, C = 0x800, Size = 16;

    static std::vector<std::byte> Pattern(uint8_t first) {
        std::vector<std::byte> bytes(Size);
        for (size_t i = 0; i < Size; ++i)
            bytes[i] = static_cast<std::byte>(first + i);
        return bytes;
    }
    static std::vector<std::byte> Reversed(std::vector<std::byte> bytes) { return {bytes.rbegin(), bytes.rend()}; }

    // Fills the client's buffers and builds the request.
    static Message Prepare(FlatMemory& memory, uint64_t base, uint64_t x_size = Size) {
        memory.Write(base + X, Pattern(0x40));
        memory.Write(base + A, Pattern(0x00));
        memory.Write(base + B, std::vector<std::byte>(Size, std::byte{0xee}));
        memory.Write(base + W, Pattern(0x10));
        Message request;
        request.data = {echo::Buffers};
        request.statics = {{base + X, x_size, 0}};
        request.sends = {{base + A, Size}};
        request.receives = {{base + B, Size}};
        request.exchanges = {{base + W, Size}};
        request.receive_list = {{base + C, 0x100}};
        return request;
    }

    // Checks what the server wrote back into the client's memory.
    static bool Verify(FlatMemory& memory, uint64_t base, const Message& reply) {
        std::vector<std::byte> w = Pattern(0x11);
        return reply.data == std::vector<uint32_t>{uint32_t{Size}} && reply.statics.size() == 1 &&
               reply.statics[0].address == base + C && reply.statics[0].size == Size &&
               memory.Snapshot(base + C, Size) == Reversed(Pattern(0x40)) &&
               memory.Snapshot(base + B, Size) == Reversed(Pattern(0x00)) && memory.Snapshot(base + W, Size) == w &&
               memory.Snapshot(base + A, Size) == Pattern(0x00);
    }
};

void BuffersCrossTheLink() {
    World world;
    Message reply;
    CHECK(world.Call(world.session, BufferCase::Prepare(world.client_memory, World::ClientScratch), reply) == Success);
    CHECK(BufferCase::Verify(world.client_memory, World::ClientScratch, reply));
    CHECK(world.Echoes(world.session, {3}));
}

void ClientCloseReachesTheServer() {
    World world;
    const uint32_t before = world.ServerHandles();
    const uint32_t second = world.Connect("echo");
    CHECK(world.Echoes(second, {2}));
    CHECK(world.ServerHandlesBecome(before + 1));
    CHECK(svc::CloseHandle(world.client_thread, second) == Success);
    CHECK(world.ServerHandlesBecome(before));
}

void ServerQuitClosesSessions() {
    World world;
    world.Stop();
    Message request, reply;
    request.data = {echo::Echo};
    CHECK(world.Call(world.session, request, reply) == SessionClosed);
    uint32_t handle;
    CHECK(world.TryConnect("echo", handle) == NotFound);
}

void HostCrashClosesSessions() {
    World world;
    CHECK(world.Echoes(world.session, {1}));
    world.host.Kill(3);
    int code;
    world.host.Wait(10000, code);
    world.stopped = true;
    // The link breaks when the reader sees the pipe close; until then a
    // request may still be queued, so wait for the result to settle.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    Message request, reply;
    request.data = {echo::Echo};
    hk::Result r;
    while ((r = world.Call(world.session, request, reply)) == Success && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(r == SessionClosed);
    uint32_t handle;
    CHECK(world.TryConnect("echo", handle) == NotFound);
}

void SessionLimitAppliesAcrossTheLink() {
    World world;
    std::vector<uint32_t> extra;
    for (uint32_t i = 1; i < echo::MaxSessions; ++i)
        extra.push_back(world.Connect("echo"));
    uint32_t handle;
    CHECK(world.TryConnect("echo", handle) == OutOfSessions);
    CHECK(svc::CloseHandle(world.client_thread, extra.back()) == Success);
    // The close reaches the host asynchronously.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    hk::Result r;
    while ((r = world.TryConnect("echo", handle)) == OutOfSessions && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(r == Success);
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*run)();
    } tests[] = {
        {"EchoAcrossProcesses", EchoAcrossProcesses},
        {"PidCrossesTheLink", PidCrossesTheLink},
        {"SubInterfaceMovesAcrossTheLink", SubInterfaceMovesAcrossTheLink},
        {"ServerSessionMovesAcrossTheLink", ServerSessionMovesAcrossTheLink},
        {"CopiedHandleCrossesAndStays", CopiedHandleCrossesAndStays},
        {"SessionGoesBackToItsServer", SessionGoesBackToItsServer},
        {"EventSignalCrossesTheLink", EventSignalCrossesTheLink},
        {"EventClearCrossesBack", EventClearCrossesBack},
        {"WaitOnMirrorWakesOnSignal", WaitOnMirrorWakesOnSignal},
        {"MirrorIsWatched", MirrorIsWatched},
        {"BuffersCrossTheLink", BuffersCrossTheLink},
        {"ClientCloseReachesTheServer", ClientCloseReachesTheServer},
        {"ServerQuitClosesSessions", ServerQuitClosesSessions},
        {"HostCrashClosesSessions", HostCrashClosesSessions},
        {"SessionLimitAppliesAcrossTheLink", SessionLimitAppliesAcrossTheLink},
    };
    for (const bool pass : {false, true}) {
        relayed = pass;
        for (const auto& test : tests) {
            const int before = failures;
            test.run();
            std::printf("%s %s%s\n", failures == before ? "PASS" : "FAIL", test.name, relayed ? " (relayed)" : "");
        }
    }
    std::printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
