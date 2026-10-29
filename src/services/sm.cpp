#include "sm.h"

#include "hk/native.h"

#include <cinttypes>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace services {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;            // message buffer
constexpr uint64_t kName = kBase + 0x200;   // port name scratch
constexpr uint64_t kHandles = kBase + 0x300; // wait list
constexpr uint64_t kProcessId = 2;          // sm's PID on Horizon is small and fixed
constexpr uint32_t kMaxClients = 0x40;

hk::Result Err(uint32_t description) { return 0x15 | (description << 9); } // module 21: sm
const hk::Result kInvalidClient = Err(2);
const hk::Result kAlreadyRegistered = Err(4);
const hk::Result kNotRegistered = Err(7);

std::string NameText(uint64_t name) {
    std::string text;
    for (int i = 0; i < 8; ++i) {
        const char ch = static_cast<char>(name >> (8 * i));
        if (!ch)
            break;
        text.push_back(ch);
    }
    return text;
}

} // namespace

struct ServiceManager::State {
    hk::Kernel& kernel;
    bool trace;
    FlatMemory memory{kBase, 0x1000};
    std::shared_ptr<hk::Process> process;
    hk_thread* thread{};
    std::thread host_thread;

    State(hk::Kernel& k, bool t) : kernel(k), trace(t) {}

    // TIPC (the protocol sm speaks since 12.0.0): the message type is the
    // command id plus 16 and arguments follow the header as raw words. A
    // reply has the request's type, and its first data word is the result.
    void Serve() {
        memory.WriteString(kName, "sm:");
        uint32_t port;
        if (const auto r = svc::ManageNamedPort(thread, kName, kMaxClients, port)) {
            std::fprintf(stderr, "sm: could not register sm: (%08x)\n", r);
            return;
        }
        std::vector<uint32_t> handles{port};
        uint32_t reply_target = 0;
        for (;;) {
            RetryDeferred();
            memory.WriteWords(kHandles, handles);
            uint32_t index = 0;
            // While requests wait for a service, wake up to look for it.
            const int64_t timeout = deferred.empty() ? -1 : 10'000'000;
            const auto r = svc::ReplyAndReceive(thread, kHandles, static_cast<uint32_t>(handles.size()), reply_target,
                                                timeout, index);
            reply_target = 0;
            if (r == hk::result::TimedOut)
                continue;
            if (r == hk::result::SessionClosed && index > 0) {
                std::erase_if(deferred, [&](const Deferred& d) { return d.session == handles[index]; });
                svc::CloseHandle(thread, handles[index]);
                handles.erase(handles.begin() + index);
                continue;
            }
            if (r) {
                std::fprintf(stderr, "sm: ReplyAndReceive failed (%08x)\n", r);
                return;
            }
            if (index == 0) {
                uint32_t session;
                if (svc::AcceptSession(thread, port, session) == hk::result::Success)
                    handles.push_back(session);
                continue;
            }
            const Message request = ReadMessage(memory, kTls);
            if (request.type == 2) { // close
                svc::CloseHandle(thread, handles[index]);
                handles.erase(handles.begin() + index);
                continue;
            }
            Message reply;
            reply.type = request.type;
            reply.data = {Dispatch(request, reply)};
            if (reply.data[0] == kNotRegistered && request.type == 16 + 1) {
                // Like the real sm, hold GetServiceHandle until the service exists.
                deferred.push_back({handles[index], request});
                if (trace)
                    std::fprintf(stderr, "sm: deferred until registered\n");
                continue;
            }
            WriteMessage(memory, kTls, reply);
            reply_target = handles[index];
        }
    }

    struct Deferred {
        uint32_t session;
        Message request;
    };
    std::vector<Deferred> deferred;

    // Answers deferred requests whose service now exists. Each reply is sent
    // with an empty wait list, which returns at once with TimedOut.
    void RetryDeferred() {
        retrying = true;
        for (auto it = deferred.begin(); it != deferred.end();) {
            Message reply;
            reply.type = it->request.type;
            reply.data = {Dispatch(it->request, reply)};
            if (reply.data[0] == kNotRegistered) {
                ++it;
                continue;
            }
            WriteMessage(memory, kTls, reply);
            uint32_t unused;
            svc::ReplyAndReceive(thread, kHandles, 0, it->session, 0, unused);
            it = deferred.erase(it);
        }
        retrying = false;
    }
    bool retrying = false;

    hk::Result Dispatch(const Message& request, Message& reply) {
        const uint32_t command = request.type >= 16 ? request.type - 16 : 0xffffffff;
        auto word = [&](size_t i) { return i < request.data.size() ? request.data[i] : 0u; };
        const uint64_t name = word(0) | static_cast<uint64_t>(word(1)) << 32;
        hk::Result result = 0;
        switch (command) {
        case 0: // RegisterClient(pid)
            break;
        case 1: { // GetServiceHandle(name) -> moved client session
            memory.WriteString(kName, NameText(name));
            uint32_t session;
            result = svc::ConnectToNamedPort(thread, kName, session);
            if (result == hk::result::NotFound)
                result = kNotRegistered;
            if (!result)
                reply.move = {session};
            break;
        }
        case 2: { // RegisterService(name, max_sessions, is_light) -> moved server port
            const uint32_t max_sessions = word(2);
            memory.WriteString(kName, NameText(name));
            uint32_t server_port;
            result = svc::ManageNamedPort(thread, kName, max_sessions, server_port);
            if (result == hk::result::InvalidState)
                result = kAlreadyRegistered;
            if (!result)
                reply.move = {server_port};
            break;
        }
        case 3: { // UnregisterService(name)
            memory.WriteString(kName, NameText(name));
            uint32_t unused;
            result = svc::ManageNamedPort(thread, kName, 0, unused);
            if (result == hk::result::NotFound)
                result = kNotRegistered;
            break;
        }
        case 4: // DetachClient
            break;
        default:
            result = kInvalidClient;
            break;
        }
        if (trace && !(retrying && result == kNotRegistered)) {
            std::fprintf(stderr, "sm: command %u", command);
            for (uint32_t w : request.data)
                std::fprintf(stderr, " %08x", w);
            std::fprintf(stderr, " [%s] -> %08x\n", NameText(name).c_str(), result);
        }
        return result;
    }
};

ServiceManager::ServiceManager(hk::Kernel& kernel, bool trace) : state_(std::make_unique<State>(kernel, trace)) {
    state_->process = kernel.CreateProcess(kProcessId, state_->memory);
    state_->thread = kernel.CreateThread(state_->process, kTls);
    state_->host_thread = std::thread([state = state_.get()] { state->Serve(); });
    state_->host_thread.detach();
}

ServiceManager::~ServiceManager() {
    // The serving thread still uses the state; keep it for the life of the host.
    (void)state_.release();
}

} // namespace services
