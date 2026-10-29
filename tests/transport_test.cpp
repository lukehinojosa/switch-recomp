// Cross-process IPC tests: the echo server runs in a separate host process
// (echo_host) with its own kernel, reached over a pipe link.
#include "echo_server.h"
#include "hk/link.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef CreateProcess // a windows.h macro that would rename hk::Kernel::CreateProcess

#include <chrono>
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

std::wstring HostPath() {
    wchar_t path[MAX_PATH];
    const DWORD size = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring result(path, size);
    return result.substr(0, result.find_last_of(L"\\/") + 1) + L"echo_host.exe";
}

struct World {
    static constexpr uint64_t ClientTls = ClientBase, ClientScratch = ClientBase + 0x200;

    World() {
        client = kernel.CreateProcess(ClientPid, client_memory);
        client_thread = kernel.CreateThread(client, ClientTls);

        // to_host: we write, the host reads. from_host: the host writes, we read.
        SECURITY_ATTRIBUTES inherit{sizeof inherit, nullptr, TRUE};
        HANDLE to_host_read, to_host_write, from_host_read, from_host_write;
        CreatePipe(&to_host_read, &to_host_write, &inherit, 0);
        CreatePipe(&from_host_read, &from_host_write, &inherit, 0);
        SetHandleInformation(to_host_write, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(from_host_read, HANDLE_FLAG_INHERIT, 0);

        std::wstring command = L"\"" + HostPath() + L"\" " +
                               std::to_wstring(reinterpret_cast<uintptr_t>(to_host_read)) + L" " +
                               std::to_wstring(reinterpret_cast<uintptr_t>(from_host_write));
        STARTUPINFOW startup{};
        startup.cb = sizeof startup;
        PROCESS_INFORMATION info{};
        const bool started =
            CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &info);
        CHECK(started);
        CloseHandle(to_host_read);
        CloseHandle(from_host_write);
        host = info.hProcess;
        CloseHandle(info.hThread);

        kernel.AttachLink(hk::OpenPipeStream(reinterpret_cast<uintptr_t>(from_host_read),
                                             reinterpret_cast<uintptr_t>(to_host_write)),
                          true);
        session = Connect("echo");
    }
    ~World() {
        Stop();
        kernel.DestroyProcess(client);
        if (host) {
            TerminateProcess(host, 1);
            CloseHandle(host);
        }
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
        if (!host || stopped)
            return;
        stopped = true;
        Message request, reply;
        request.data = {echo::Quit};
        CHECK(Call(session, request, reply) == Success);
        CHECK(WaitForSingleObject(host, 10000) == WAIT_OBJECT_0);
        DWORD code = 1;
        GetExitCodeProcess(host, &code);
        CHECK(code == 0);
    }

    hk::Kernel kernel;
    FlatMemory client_memory{ClientBase, 0x1000};
    std::shared_ptr<hk::Process> client;
    hk_thread* client_thread{};
    HANDLE host{};
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
    TerminateProcess(world.host, 3);
    WaitForSingleObject(world.host, 10000);
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
        {"BuffersCrossTheLink", BuffersCrossTheLink},
        {"ClientCloseReachesTheServer", ClientCloseReachesTheServer},
        {"ServerQuitClosesSessions", ServerQuitClosesSessions},
        {"HostCrashClosesSessions", HostCrashClosesSessions},
        {"SessionLimitAppliesAcrossTheLink", SessionLimitAppliesAcrossTheLink},
    };
    for (const auto& test : tests) {
        const int before = failures;
        test.run();
        std::printf("%s %s\n", failures == before ? "PASS" : "FAIL", test.name);
    }
    std::printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
