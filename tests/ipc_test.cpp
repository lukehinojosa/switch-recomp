// Kernel IPC tests: an authored echo server and a client in two guest
// processes with separate address spaces, both driving the kernel only
// through hk_svc.
#include "echo_server.h"

#include <chrono>
#include <cstdio>
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

constexpr uint64_t ServerBase = 0x10000000, ClientBase = 0x20000000;
constexpr uint64_t ServerPid = 0x51, ClientPid = 0x7c;

struct World {
    static constexpr uint64_t ServerTls = ServerBase, ServerScratch = ServerBase + 0x200;
    static constexpr uint64_t ClientTls = ClientBase, ClientScratch = ClientBase + 0x200;

    World() {
        server = kernel.CreateProcess(ServerPid, server_memory);
        client = kernel.CreateProcess(ClientPid, client_memory);
        server_thread = kernel.CreateThread(server, ServerTls);
        client_thread = kernel.CreateThread(client, ClientTls);
        thread = std::thread([this] {
            server_result = echo::RunServer(server_thread, server_memory, ServerTls, ServerScratch);
        });
        session = Connect("echo");
    }
    ~World() {
        Stop();
        kernel.DestroyProcess(client);
        kernel.DestroyProcess(server);
    }

    hk::Result TryConnect(const char* name, uint32_t& handle) {
        client_memory.WriteString(ClientScratch, name);
        return svc::ConnectToNamedPort(client_thread, ClientScratch, handle);
    }
    // The server registers its port asynchronously, so retry until it exists.
    uint32_t Connect(const char* name) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
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
    void Stop() {
        if (!thread.joinable())
            return;
        Message request, reply;
        request.data = {echo::Quit};
        CHECK(Call(session, request, reply) == Success);
        thread.join();
        CHECK(server_result == Success);
    }
    // Waits for the server thread to reach a handle count after peer activity.
    bool ServerHandlesBecome(size_t count) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (kernel.HandleCount(server) != count) {
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    hk::Kernel kernel;
    TestMemory server_memory{ServerBase, 0x1000}, client_memory{ClientBase, 0x1000};
    std::shared_ptr<hk::Process> server, client;
    hk_thread* server_thread{};
    hk_thread* client_thread{};
    std::thread thread;
    hk::Result server_result = Success;
    uint32_t session{};
};

void EchoRoundTrip() {
    World world;
    CHECK(world.Echoes(world.session, {0xdeadbeef, 42, 7}));
    CHECK(world.Echoes(world.session, {}));
}

void PidIsWrittenByTheKernel() {
    World world;
    Message request, reply;
    request.send_pid = true;
    request.pid = 0x1234; // whatever the client claims is overwritten
    request.data = {echo::WhoAmI};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(reply.data == (std::vector<uint32_t>{static_cast<uint32_t>(ClientPid), 0}));
}

void ServerMovesSubInterfaceToClient() {
    World world;
    const size_t before = world.kernel.HandleCount(world.client);
    Message request, reply;
    request.data = {echo::OpenSub};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(reply.move.size() == 1);
    CHECK(world.kernel.HandleCount(world.client) == before + 1);
    if (reply.move.size() == 1)
        CHECK(world.Echoes(reply.move[0], {9, 8}));
}

void ClientMovesServerSessionToServer() {
    World world;
    uint32_t server_end, client_end;
    CHECK(svc::CreateSession(world.client_thread, server_end, client_end) == Success);
    Message request, reply;
    request.move = {server_end};
    request.data = {echo::Adopt};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(svc::CloseHandle(world.client_thread, server_end) == InvalidHandle); // moved away
    CHECK(world.Echoes(client_end, {5}));
}

void CopiedHandleStaysWithSender() {
    World world;
    CHECK(world.Echoes(world.session, {1})); // the server has accepted the session
    const size_t server_before = world.kernel.HandleCount(world.server);
    uint32_t server_end, client_end;
    CHECK(svc::CreateSession(world.client_thread, server_end, client_end) == Success);
    Message request, reply;
    request.copy = {client_end};
    request.data = {echo::Echo};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(world.kernel.HandleCount(world.server) == server_before + 1);
    CHECK(svc::CloseHandle(world.client_thread, client_end) == Success);
    CHECK(svc::CloseHandle(world.client_thread, server_end) == Success);
}

void BufferDescriptorsAreRejectedBeforeDelivery() {
    World world;
    CHECK(world.Echoes(world.session, {1}));
    const size_t server_before = world.kernel.HandleCount(world.server);
    Message request, reply;
    request.extra_header0 = 1u << 16; // one X (send static) descriptor
    request.data = {echo::Echo};
    CHECK(world.Call(world.session, request, reply) == NotImplemented);
    CHECK(world.kernel.HandleCount(world.server) == server_before);
    CHECK(world.Echoes(world.session, {2}));
}

void ClientCloseIsReportedToServer() {
    World world;
    CHECK(world.Echoes(world.session, {1}));
    const size_t server_before = world.kernel.HandleCount(world.server);
    const uint32_t second = world.Connect("echo");
    CHECK(world.Echoes(second, {2}));
    CHECK(world.ServerHandlesBecome(server_before + 1));
    CHECK(svc::CloseHandle(world.client_thread, second) == Success);
    CHECK(world.ServerHandlesBecome(server_before));
}

void ServerCloseIsReportedToClient() {
    World world;
    world.Stop();
    CHECK(world.kernel.HandleCount(world.server) == 0);
    CHECK(!world.Echoes(world.session, {1}));
    Message request, reply;
    request.data = {echo::Echo};
    CHECK(world.Call(world.session, request, reply) == SessionClosed);
    uint32_t handle;
    CHECK(world.TryConnect("echo", handle) == NotFound); // closing the port unregistered it
}

void SessionLimitIsEnforced() {
    World world;
    std::vector<uint32_t> extra;
    for (uint32_t i = 1; i < echo::MaxSessions; ++i)
        extra.push_back(world.Connect("echo"));
    uint32_t handle;
    CHECK(world.TryConnect("echo", handle) == OutOfSessions);
    CHECK(svc::CloseHandle(world.client_thread, extra.back()) == Success);
    CHECK(world.TryConnect("echo", handle) == Success);
}

void BadArgumentsAreRejected() {
    World world;
    Message request, reply;
    request.data = {echo::Echo};
    CHECK(world.Call(0x9999, request, reply) == InvalidHandle);
    uint32_t handle;
    CHECK(world.TryConnect("nope", handle) == NotFound);
    world.client_memory.WriteString(World::ClientScratch, "twelve-chars");
    CHECK(svc::ConnectToNamedPort(world.client_thread, World::ClientScratch, handle) == OutOfRange);
    CHECK(svc::ConnectToNamedPort(world.client_thread, 0x1234, handle) == InvalidPointer);
    hk_regs regs{};
    CHECK(svc::Call(world.client_thread, 0x7f, regs) == NotImplemented);
}

void AddressSpacesStaySeparate() {
    World world;
    for (uint64_t at = ClientBase + 0x400; at < ClientBase + 0x1000; at += 4)
        world.client_memory.WriteWords(at, std::vector<uint32_t>{0xa5a5a5a5});
    const auto before = world.client_memory.Snapshot(ClientBase + 0x400, 0xc00);
    Message request, reply;
    request.data = {echo::OpenSub};
    CHECK(world.Call(world.session, request, reply) == Success);
    CHECK(world.Echoes(world.session, {3, 4}));
    CHECK(world.client_memory.Snapshot(ClientBase + 0x400, 0xc00) == before);
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*run)();
    } tests[] = {
        {"EchoRoundTrip", EchoRoundTrip},
        {"PidIsWrittenByTheKernel", PidIsWrittenByTheKernel},
        {"ServerMovesSubInterfaceToClient", ServerMovesSubInterfaceToClient},
        {"ClientMovesServerSessionToServer", ClientMovesServerSessionToServer},
        {"CopiedHandleStaysWithSender", CopiedHandleStaysWithSender},
        {"BufferDescriptorsAreRejectedBeforeDelivery", BufferDescriptorsAreRejectedBeforeDelivery},
        {"ClientCloseIsReportedToServer", ClientCloseIsReportedToServer},
        {"ServerCloseIsReportedToClient", ServerCloseIsReportedToClient},
        {"SessionLimitIsEnforced", SessionLimitIsEnforced},
        {"BadArgumentsAreRejected", BadArgumentsAreRejected},
        {"AddressSpacesStaySeparate", AddressSpacesStaySeparate},
    };
    for (const auto& test : tests) {
        const int before = failures;
        test.run();
        std::printf("%s %s\n", failures == before ? "PASS" : "FAIL", test.name);
    }
    std::printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
