#include "sm.h"

#include "hk/native.h"

#include <cinttypes>
#include <cstdio>
#include <optional>
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
const hk::Result kUnknownCommand = 0xA | (221 << 9); // sf: the command is not served

constexpr uint32_t kInMagic = 0x49434653;  // "SFCI"
constexpr uint32_t kOutMagic = 0x4F434653; // "SFCO"

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
    // Titles built with older SDKs still speak CMIF to sm, which it accepts
    // too: the same commands behind a CMIF header.
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
            if (Answer(request, reply) == kNotRegistered && Command(request) == 1) {
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
            if (Answer(it->request, reply) == kNotRegistered) {
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

    static bool IsCmif(const Message& m) { return m.type >= 4 && m.type <= 7; }

    // Where a CMIF request's header is, or none.
    static std::optional<size_t> CmifHeader(const Message& m) {
        const size_t at = CmifPadding(m);
        if (!IsCmif(m) || m.data.size() < at + 4 || m.data[at] != kInMagic)
            return std::nullopt;
        return at;
    }

    // The command a request names in either protocol; ~0 for none.
    static uint32_t Command(const Message& m) {
        if (m.type >= 16)
            return m.type - 16;
        const auto at = CmifHeader(m);
        return at && (m.type == 4 || m.type == 6) ? m.data[*at + 2] : ~0u;
    }

    // Builds the reply to a request in its own protocol; returns the result.
    hk::Result Answer(const Message& request, Message& reply) {
        if (!IsCmif(request)) {
            reply.type = request.type;
            const hk::Result result = Dispatch(Command(request), request.data, reply);
            reply.data = {result};
            return result;
        }
        hk::Result result = kUnknownCommand;
        std::vector<uint32_t> output;
        if (const auto at = CmifHeader(request)) {
            const std::vector<uint32_t> args(request.data.begin() + static_cast<ptrdiff_t>(*at + 4), request.data.end());
            if (request.type == 4 || request.type == 6) {
                result = Dispatch(request.data[*at + 2], args, reply);
            } else if (request.data[*at + 2] == 3) { // control: QueryPointerBufferSize
                result = 0;
                output.push_back(0); // sm takes no pointer buffers
            }
        }
        if (result)
            reply.move.clear();
        reply.type = 0;
        reply.data.assign(CmifPadding(reply), 0);
        reply.data.insert(reply.data.end(), {kOutMagic, 0, result, 0});
        reply.data.insert(reply.data.end(), output.begin(), output.end());
        return result;
    }

    hk::Result Dispatch(uint32_t command, const std::vector<uint32_t>& args, Message& reply) {
        auto word = [&](size_t i) { return i < args.size() ? args[i] : 0u; };
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
            for (uint32_t w : args)
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
