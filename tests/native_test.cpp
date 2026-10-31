// Native services: the CMIF host (plain sessions, sub-interfaces as moved
// sessions, domains) and sm (TIPC, deferral until a service exists), driven
// by a client process through hk_svc.
#include "hk/native.h"
#include "services/native.h"
#include "services/sm.h"

#include <chrono>
#include <cstdio>
#include <future>
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

constexpr uint64_t Base = 0x20000000, Tls = Base, Name = Base + 0x200;
constexpr uint32_t InMagic = 0x49434653, OutMagic = 0x4F434653;

// command 1: returns a Child; command 2 on a Child: returns its input + 1.
class Child final : public services::Interface {
public:
    const char* Name() const override { return "test child"; }
    hk::Result Handle(const services::Request& request, services::Response& response) override {
        if (request.command != 2)
            return services::MakeResult(10, 221);
        response.Out(request.In<uint32_t>(0) + 1);
        return 0;
    }
};

class Root final : public services::Interface {
public:
    const char* Name() const override { return "test"; }
    hk::Result Handle(const services::Request& request, services::Response& response) override {
        if (request.command != 1)
            return services::MakeResult(10, 221);
        response.objects.push_back(std::make_shared<Child>());
        return 0;
    }
};

struct Reply {
    hk::Result kernel{}, result{};
    std::vector<uint32_t> raw, move, objects;
};

struct Client {
    explicit Client(hk::Kernel& kernel) {
        process = kernel.CreateProcess(0x90, memory);
        thread = kernel.CreateThread(process, Tls);
    }

    uint32_t Connect(const char* name) {
        memory.WriteString(Name, name);
        uint32_t session = 0;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (svc::ConnectToNamedPort(thread, Name, session) == NotFound && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return session;
    }

    // type 4 or 5; a domain request names object (0: none) and expects a
    // domain reply carrying out_objects ids after the output.
    Reply Call(uint32_t session, uint32_t type, uint32_t command, std::vector<uint32_t> raw, uint32_t object = 0,
               uint32_t domain_command = 1, size_t out_objects = 0) {
        Message request;
        request.type = type;
        request.data.assign(2, 0); // data starts at word 2: 2 words of padding to 16 bytes
        std::vector<uint32_t> body{InMagic, 0, command, 0};
        body.insert(body.end(), raw.begin(), raw.end());
        if (object) {
            request.data.insert(request.data.end(),
                                {domain_command | static_cast<uint32_t>(body.size() * 4) << 16, object, 0, 0});
        }
        request.data.insert(request.data.end(), body.begin(), body.end());
        request.data.insert(request.data.end(), 2, 0);
        WriteMessage(memory, Tls, request);
        Reply reply;
        reply.kernel = svc::SendSyncRequest(thread, session);
        if (reply.kernel)
            return reply;
        const Message message = ReadMessage(memory, Tls);
        reply.move = message.move;
        const uint32_t word = 2 + (message.move.empty() ? 0 : 1) + static_cast<uint32_t>(message.move.size());
        const size_t pad = (4 - word % 4) % 4;
        size_t at = pad;
        if (object)
            at += 4; // domain reply header
        // The data ends with the rest of the 16 bytes reserved for alignment.
        if (message.data.size() < at + 4 + (4 - pad) || message.data[at] != OutMagic) {
            reply.result = ~0u;
            return reply;
        }
        reply.result = message.data[at + 2];
        reply.raw.assign(message.data.begin() + static_cast<ptrdiff_t>(at + 4),
                         message.data.end() - static_cast<ptrdiff_t>(4 - pad));
        if (out_objects && reply.raw.size() >= out_objects) {
            reply.objects.assign(reply.raw.end() - static_cast<ptrdiff_t>(out_objects), reply.raw.end());
            reply.raw.resize(reply.raw.size() - out_objects);
        }
        return reply;
    }

    FlatMemory memory{Base, 0x1000};
    std::shared_ptr<hk::Process> process;
    hk_thread* thread{};
};

void SubInterfaceIsAMovedSession() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("test");
    CHECK(session != 0);
    const Reply opened = client.Call(session, 4, 1, {});
    CHECK(opened.kernel == Success && opened.result == 0 && opened.move.size() == 1);
    if (opened.move.size() != 1)
        return;
    const Reply answered = client.Call(opened.move[0], 4, 2, {41});
    CHECK(answered.result == 0 && !answered.raw.empty() && answered.raw[0] == 42);
    CHECK(client.Call(session, 4, 9, {}).result != 0); // unknown command
}

// The same interfaces over TIPC: the command in the message type, a reply
// of the same type starting with the result, and a sub-interface as a moved
// session that speaks TIPC too.
void TipcRequestsAreServed() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("test");
    CHECK(session != 0);
    auto call = [&](uint32_t handle, uint32_t command, std::vector<uint32_t> data) {
        Message request;
        request.type = 16 + command;
        request.data = std::move(data);
        WriteMessage(client.memory, Tls, request);
        CHECK(svc::SendSyncRequest(client.thread, handle) == Success);
        return ReadMessage(client.memory, Tls);
    };
    const Message opened = call(session, 1, {});
    CHECK(opened.type == 17 && opened.data.size() == 1 && opened.data[0] == 0 && opened.move.size() == 1);
    if (opened.move.size() != 1)
        return;
    const Message answered = call(opened.move[0], 2, {41});
    CHECK(answered.type == 18 && answered.data == (std::vector<uint32_t>{0, 42}));
    const Message unknown = call(session, 9, {});
    CHECK(unknown.type == 25 && unknown.data.size() == 1 && unknown.data[0] != 0);
}

void CloneGivesASecondSession() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("test");
    const Reply cloned = client.Call(session, 5, 4, {0}); // CloneCurrentObjectEx(tag)
    CHECK(cloned.kernel == Success && cloned.result == 0 && cloned.move.size() == 1);
    if (cloned.move.size() == 1)
        CHECK(client.Call(cloned.move[0], 4, 1, {}).move.size() == 1); // the clone serves the root
}

void DomainCarriesObjectsById() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("test");
    const Reply converted = client.Call(session, 5, 0, {}); // ConvertCurrentObjectToDomain
    CHECK(converted.result == 0 && !converted.raw.empty());
    if (converted.raw.empty())
        return;
    const uint32_t root = converted.raw[0];
    const Reply opened = client.Call(session, 4, 1, {}, root, 1, 1);
    CHECK(opened.result == 0 && opened.move.empty() && opened.objects.size() == 1);
    if (opened.objects.size() != 1)
        return;
    const uint32_t child = opened.objects[0];
    CHECK(child != root);
    const Reply answered = client.Call(session, 4, 2, {9}, child);
    CHECK(answered.result == 0 && !answered.raw.empty() && answered.raw[0] == 10);
    CHECK(client.Call(session, 4, 0, {}, child, 2).kernel == Success); // close the child
    CHECK(client.Call(session, 4, 2, {9}, child).result != 0);
    CHECK(client.Call(session, 4, 1, {}, root, 1, 1).result == 0); // the root still works
}

void DomainCloneKeepsItsObjects() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("test");
    const Reply converted = client.Call(session, 5, 0, {});
    CHECK(converted.result == 0 && !converted.raw.empty());
    if (converted.raw.empty())
        return;
    const Reply cloned = client.Call(session, 5, 2, {}); // CloneCurrentObject
    CHECK(cloned.result == 0 && cloned.move.size() == 1);
    if (cloned.move.size() != 1)
        return;
    // The clone is a domain with the same object ids.
    CHECK(client.Call(cloned.move[0], 4, 1, {}, converted.raw[0], 1, 1).objects.size() == 1);
}

// A service that hands out shared memory and an event.
class Sharing final : public services::Interface {
public:
    const char* Name() const override { return "sharing"; }
    hk::Result Handle(const services::Request& request, services::Response& response) override {
        if (request.command == 1) {
            std::vector<std::byte> page(0x1000, std::byte{0x5a});
            response.copy.push_back(request.create_shared_memory(std::move(page)));
            return 0;
        }
        if (request.command == 2) {
            response.copy.push_back(request.create_event());
            return 0;
        }
        return services::MakeResult(10, 221);
    }
};

void SharedMemoryArrivesAsASnapshot() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::NativeHost host(kernel, false);
    host.Add("sharing", 4, [] { return std::make_shared<Sharing>(); });
    host.Start();
    Client client(kernel);
    const uint32_t session = client.Connect("sharing");
    Message request;
    request.type = 4;
    request.data = {0, 0, InMagic, 0, 1, 0, 0, 0};
    WriteMessage(client.memory, Tls, request);
    CHECK(svc::SendSyncRequest(client.thread, session) == Success);
    const Message reply = ReadMessage(client.memory, Tls);
    CHECK(reply.copy.size() == 1);
    if (reply.copy.size() != 1)
        return;
    constexpr uint64_t Where = Base;
    hk_regs regs{};
    regs.x[0] = reply.copy[0];
    regs.x[1] = Where;
    regs.x[2] = 0x1000;
    regs.x[3] = 1;
    CHECK(svc::Call(client.thread, HK_SVC_MAP_SHARED_MEMORY, regs) == Success);
    CHECK(client.memory.Snapshot(Where + 0x800, 4) == std::vector<std::byte>(4, std::byte{0x5a}));
    regs.x[0] = reply.copy[0]; // the call left its result in x0
    regs.x[2] = 0x2000;        // the size must match
    CHECK(svc::Call(client.thread, HK_SVC_MAP_SHARED_MEMORY, regs) == InvalidAddress);

    request.data[4] = 2; // an event: valid to wait on, never signalled
    WriteMessage(client.memory, Tls, request);
    CHECK(svc::SendSyncRequest(client.thread, session) == Success);
    const Message event = ReadMessage(client.memory, Tls);
    CHECK(event.copy.size() == 1);
    if (event.copy.size() == 1) {
        client.memory.WriteWords(Name, std::span(&event.copy[0], 1));
        uint32_t index;
        CHECK(svc::WaitSynchronization(client.thread, Name, 1, 0, index) == TimedOut);
    }
}

void SmDefersUntilRegistered() {
    hk::Kernel& kernel = *new hk::Kernel; // outlives the test: services keep serving
    services::ServiceManager sm(kernel);
    Client client(kernel);
    const uint32_t session = client.Connect("sm:");
    CHECK(session != 0);
    // GetServiceHandle("late") over TIPC: type 16 + 1, the name as two words.
    auto ask = std::async(std::launch::async, [&] {
        Message request;
        request.type = 17;
        request.data = {0x6574616c, 0}; // "late"
        WriteMessage(client.memory, Tls, request);
        const hk::Result r = svc::SendSyncRequest(client.thread, session);
        return std::make_pair(r, ReadMessage(client.memory, Tls));
    });
    CHECK(ask.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout);
    services::NativeHost host(kernel, false);
    host.Add("late", 4, [] { return std::make_shared<Root>(); });
    host.Start();
    CHECK(ask.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    const auto [result, reply] = ask.get();
    CHECK(result == Success);
    CHECK(reply.type == 17 && !reply.data.empty() && reply.data[0] == 0 && reply.move.size() == 1);
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*run)();
    } tests[] = {
        {"SubInterfaceIsAMovedSession", SubInterfaceIsAMovedSession},
        {"CloneGivesASecondSession", CloneGivesASecondSession},
        {"DomainCarriesObjectsById", DomainCarriesObjectsById},
        {"DomainCloneKeepsItsObjects", DomainCloneKeepsItsObjects},
        {"SharedMemoryArrivesAsASnapshot", SharedMemoryArrivesAsASnapshot},
        {"TipcRequestsAreServed", TipcRequestsAreServed},
        {"SmDefersUntilRegistered", SmDefersUntilRegistered},
    };
    for (const auto& test : tests) {
        const int before = failures;
        test.run();
        std::printf("%s %s\n", failures == before ? "PASS" : "FAIL", test.name);
    }
    std::printf("%d failure(s)\n", failures);
    // Native servers keep serving on detached threads; leave without joining.
    std::fflush(stdout);
    std::_Exit(failures ? 1 : 0);
}
