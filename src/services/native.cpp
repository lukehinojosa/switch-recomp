#include "native.h"

#include "hk/native.h"

#include <cstdio>
#include <algorithm>
#include <map>
#include <thread>

namespace services {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;
constexpr uint64_t kHandles = kBase + 0x200;    // wait list, up to 0x40 handles
constexpr uint64_t kNames = kBase + 0x300;      // port name scratch
constexpr uint64_t kReceive = kBase + 0x1000;   // where incoming X buffers land
constexpr uint64_t kReceiveSize = 0x1000;
constexpr uint64_t kReplyStatics = kBase + 0x2000; // X buffers a reply sends
constexpr uint64_t kReplyStaticsSize = 0x10000;
constexpr uint64_t kMemorySize = 0x2000 + kReplyStaticsSize;
constexpr uint64_t kIpcArea = 64u << 20;
constexpr uint64_t kProcessId = 3;
constexpr uint32_t kMaxHandles = 0x40;
constexpr uint32_t kReceiveListWord = 0x38;

constexpr uint32_t kInMagic = 0x49434653;  // "SFCI"
constexpr uint32_t kOutMagic = 0x4F434653; // "SFCO"
const hk::Result kUnknownCommand = MakeResult(10, 221);

enum MessageType : uint32_t { Close = 2, Request4 = 4, Control = 5, RequestWithContext = 6, ControlWithContext = 7 };
// TIPC, which some services speak since 12.0.0: the message type is the
// command plus 16 and the data words are the arguments, with no header; type
// 15 closes. A reply keeps the request's type and starts with the result.
constexpr uint32_t kTipcClose = 15, kTipcFirst = 16;

uint32_t Padding(const Message& m) { return CmifPadding(m); }

} // namespace

std::vector<std::byte> Request::InBuffer(size_t index) const {
    for (const auto* list : {&statics, &sends}) {
        if (index < list->size() && (*list)[index].size) {
            std::vector<std::byte> bytes((*list)[index].size);
            if (read((*list)[index].address, bytes))
                return bytes;
        }
    }
    return {};
}

bool Request::OutBuffer(std::span<const std::byte> bytes, size_t index) const {
    if (index < receives.size() && receives[index].size >= bytes.size() && receives[index].size)
        return write(receives[index].address, bytes);
    if (!pointer_out)
        return false;
    if (pointer_out->size() <= index)
        pointer_out->resize(index + 1);
    (*pointer_out)[index].assign(bytes.begin(), bytes.end());
    return true;
}

struct NativeHost::State {
    hk::Kernel& kernel;
    bool trace;
    FlatMemory memory{kBase, kMemorySize, kIpcArea};
    std::shared_ptr<hk::Process> process;
    hk_thread* thread{};
    std::thread host_thread;

    struct Port {
        std::string name;
        uint32_t max_sessions;
        Factory factory;
        uint32_t handle{};
    };
    std::vector<Port> ports;
    // A session serves one interface, or, once the client converts it to a
    // domain, a table of objects addressed by id.
    struct Session {
        std::shared_ptr<Interface> object;
        bool domain = false;
        std::map<uint32_t, std::shared_ptr<Interface>> objects;
        uint32_t next_id = 1;
    };
    // Wait list: ports first, then sessions.
    std::vector<uint32_t> handles;
    std::map<uint32_t, Session> sessions;
    uint32_t cloned_domain = 0; // client end of a domain clone, for the reply

    State(hk::Kernel& k, bool t) : kernel(k), trace(t) {}

    void Serve() {
        for (auto& port : ports) {
            memory.WriteString(kNames, port.name);
            if (const auto r = svc::ManageNamedPort(thread, kNames, port.max_sessions, port.handle)) {
                std::fprintf(stderr, "native: could not register %s (%08x)\n", port.name.c_str(), r);
                return;
            }
            handles.push_back(port.handle);
        }
        uint32_t reply_target = 0;
        for (;;) {
            if (!reply_target) {
                Message idle;
                idle.type = 0;
                WithReceiveList(idle);
                WriteMessage(memory, kTls, idle);
            }
            memory.WriteWords(kHandles, handles);
            uint32_t index = 0;
            const auto r = svc::ReplyAndReceive(thread, kHandles, static_cast<uint32_t>(handles.size()), reply_target,
                                                -1, index);
            reply_target = 0;
            if (r == hk::result::SessionClosed && index >= ports.size()) {
                Drop(index);
                continue;
            }
            if (r) {
                std::fprintf(stderr, "native: ReplyAndReceive failed (%08x)\n", r);
                return;
            }
            if (index < ports.size()) {
                uint32_t session;
                if (svc::AcceptSession(thread, handles[index], session) == hk::result::Success) {
                    if (handles.size() >= kMaxHandles) {
                        svc::CloseHandle(thread, session);
                        continue;
                    }
                    handles.push_back(session);
                    sessions[session].object = ports[index].factory();
                }
                continue;
            }
            const uint32_t session = handles[index];
            const Message message = ReadMessage(memory, kTls);
            if (message.type == Close || message.type == kTipcClose) {
                Drop(index);
                continue;
            }
            Message reply;
            if (message.type >= kTipcFirst)
                ServeTipc(session, message, reply);
            else
                Serve(session, message, reply);
            WithReceiveList(reply);
            WriteMessage(memory, kTls, reply);
            reply_target = session;
        }
    }

    void WithReceiveList(Message& message) {
        message.receive_list = {{kReceive, kReceiveSize}};
        message.receive_list_word = kReceiveListWord;
    }

    void Drop(uint32_t index) {
        if (trace) {
            auto it = sessions.find(handles[index]);
            std::fprintf(stderr, "native: %s session %08x closed\n",
                         it != sessions.end() && it->second.object ? it->second.object->Name() : "a",
                         handles[index]);
        }
        svc::CloseHandle(thread, handles[index]);
        sessions.erase(handles[index]);
        handles.erase(handles.begin() + index);
    }

    void Serve(uint32_t handle, const Message& message, Message& reply) {
        Session& session = sessions[handle];
        const uint32_t type = message.type;
        const bool control = type == Control || type == ControlWithContext;
        const bool domain = session.domain && !control;
        const auto& data = message.data;
        size_t at = Padding(message);
        size_t end = data.size();

        // Domain requests start with a header naming the target object.
        std::shared_ptr<Interface> object = session.object;
        uint32_t domain_type = 1;
        std::vector<uint32_t> in_objects;
        if (domain) {
            if (data.size() < at + 4) {
                return Finish(reply, session, domain, MakeResult(10, 211), {});
            }
            domain_type = data[at] & 0xff;
            const uint32_t input_objects = (data[at] >> 8) & 0xff;
            const uint32_t size = data[at] >> 16;
            const uint32_t id = data[at + 1];
            at += 4;
            end = std::min(data.size(), at + size / 4);
            for (uint32_t i = 0; i < input_objects && end + i < data.size(); ++i)
                in_objects.push_back(data[end + i]);
            if (domain_type == 2) { // close the object
                session.objects.erase(id);
                return Finish(reply, session, domain, 0, {});
            }
            auto it = session.objects.find(id);
            if (domain_type != 1 || it == session.objects.end())
                return Finish(reply, session, domain, MakeResult(10, 211), {});
            object = it->second;
        }

        Request request;
        Response response;
        std::vector<std::vector<std::byte>> pointer_out;
        request.pointer_out = &pointer_out;
        hk::Result result = 0;
        if (end < at + 4 || data[at] != kInMagic) {
            result = kUnknownCommand;
        } else {
            request.command = data[at + 2];
            Prepare(request, message, at + 4, end);
            if (control)
                result = HandleControl(request, response, session);
            else if (type == Request4 || type == RequestWithContext)
                result = object->Handle(request, response);
            else
                result = kUnknownCommand;
            if (trace || result == kUnknownCommand)
                Log(*object, control ? " control" : "", request, result);
        }
        if (!result) {
            // Output for C buffers goes back as X buffers; set before Finish,
            // since their descriptors move the CMIF header.
            uint64_t place = kReplyStatics;
            for (uint32_t i = 0; i < pointer_out.size(); ++i) {
                const auto& bytes = pointer_out[i];
                if (place + bytes.size() > kReplyStatics + kReplyStaticsSize)
                    break;
                memory.Write(place, bytes);
                reply.statics.push_back({place, bytes.size(), i});
                place = (place + bytes.size() + 15) & ~uint64_t{15};
            }
        }
        Finish(reply, session, domain, result, std::move(response));
    }

    // Fills in a request's arguments (data words from to end), handles,
    // buffers and the host's helpers.
    void Prepare(Request& request, const Message& message, size_t from, size_t end) {
        request.pid = message.pid;
        request.copy = message.copy;
        request.move = message.move;
        for (size_t i = from; i < end; ++i) {
            const uint32_t word = message.data[i];
            const auto* bytes = reinterpret_cast<const std::byte*>(&word);
            request.raw.insert(request.raw.end(), bytes, bytes + 4);
        }
        for (const auto& x : message.statics)
            request.statics.push_back({x.address, x.size});
        for (const auto& b : message.sends)
            request.sends.push_back({b.address, b.size});
        for (const auto& b : message.receives)
            request.receives.push_back({b.address, b.size});
        for (const auto& b : message.exchanges)
            request.exchanges.push_back({b.address, b.size});
        request.read = [this](uint64_t a, std::span<std::byte> out) { return memory.Read(a, out); };
        request.write = [this](uint64_t a, std::span<const std::byte> in) { return memory.Write(a, in); };
        request.create_event = [this] {
            uint32_t writable = 0, readable = 0;
            svc::CreateEvent(thread, writable, readable);
            return readable;
        };
        request.create_event_pair = [this] {
            uint32_t writable = 0, readable = 0;
            svc::CreateEvent(thread, writable, readable);
            return std::pair{writable, readable};
        };
        request.signal_event = [this](uint32_t writable) { svc::SignalEvent(thread, writable); };
        request.transfer_memory = [this](uint32_t handle, hk::Kernel::TransferRange& out) {
            return kernel.FindTransferMemory(process, handle, out);
        };
        request.clear_event = [this](uint32_t writable) { svc::ClearEvent(thread, writable); };
        request.create_shared_memory = [this](std::vector<std::byte> contents) {
            return kernel.CreateSharedMemory(process, std::move(contents));
        };
    }

    void Log(const Interface& object, const char* kind, const Request& request, hk::Result result) {
        std::string input;
        for (size_t i = 0; i < request.raw.size() && i < 16; ++i) {
            char hex[4];
            std::snprintf(hex, sizeof hex, "%02x", static_cast<unsigned>(request.raw[i]));
            input += hex;
        }
        std::fprintf(stderr, "native: %s%s command %u (%zu bytes in: %s) -> %08x\n", object.Name(), kind,
                     request.command, request.raw.size(), input.c_str(), result);
    }

    // A TIPC request. Returned interfaces become moved sessions, which speak
    // TIPC too; there are no domains, buffers come back only through B.
    void ServeTipc(uint32_t handle, const Message& message, Message& reply) {
        Session& session = sessions[handle];
        Request request;
        Response response;
        request.command = message.type - kTipcFirst;
        Prepare(request, message, 0, message.data.size());
        hk::Result result = session.object->Handle(request, response);
        if (trace || result == kUnknownCommand)
            Log(*session.object, " (TIPC)", request, result);
        reply.type = message.type;
        if (!result) {
            reply.copy = response.copy;
            for (auto& sub : response.objects) {
                uint32_t server, client;
                if (handles.size() >= kMaxHandles ||
                    svc::CreateSession(thread, server, client) != hk::result::Success) {
                    result = MakeResult(10, 3); // out of sessions
                    break;
                }
                handles.push_back(server);
                sessions[server].object = sub;
                reply.move.push_back(client);
            }
        }
        if (result) {
            reply.copy.clear();
            reply.move.clear();
            response.raw.clear();
        }
        reply.data = {result};
        response.raw.resize((response.raw.size() + 3) & ~size_t{3});
        for (size_t i = 0; i < response.raw.size(); i += 4) {
            uint32_t word;
            std::memcpy(&word, response.raw.data() + i, 4);
            reply.data.push_back(word);
        }
    }

    // Builds the reply: returned interfaces become domain object ids or moved
    // sessions, then the (domain header,) CMIF header, output and object ids.
    void Finish(Message& reply, Session& session, bool domain, hk::Result result, Response response) {
        reply.type = 0;
        std::vector<uint32_t> out_objects;
        if (!result) {
            reply.copy = response.copy;
            if (cloned_domain) {
                reply.move.push_back(cloned_domain);
                cloned_domain = 0;
            }
            for (auto& sub : response.objects) {
                if (domain) {
                    const uint32_t id = session.next_id++;
                    session.objects[id] = sub;
                    out_objects.push_back(id);
                    continue;
                }
                uint32_t server, client;
                if (handles.size() >= kMaxHandles ||
                    svc::CreateSession(thread, server, client) != hk::result::Success) {
                    result = MakeResult(10, 3); // out of sessions
                    break;
                }
                handles.push_back(server);
                sessions[server].object = sub;
                reply.move.push_back(client);
            }
        }
        if (result) {
            reply.copy.clear();
            reply.move.clear();
            out_objects.clear();
            response.raw.clear();
        }
        reply.data.assign(Padding(reply), 0);
        if (domain)
            reply.data.insert(reply.data.end(), {static_cast<uint32_t>(out_objects.size()), 0, 0, 0});
        reply.data.insert(reply.data.end(), {kOutMagic, 0, result, 0});
        response.raw.resize((response.raw.size() + 3) & ~size_t{3});
        for (size_t i = 0; i < response.raw.size(); i += 4) {
            uint32_t word;
            std::memcpy(&word, response.raw.data() + i, 4);
            reply.data.push_back(word);
        }
        reply.data.insert(reply.data.end(), out_objects.begin(), out_objects.end());
        // Like a request, the data size counts the whole 16 bytes reserved
        // for aligning the header, whatever part the padding used.
        reply.data.insert(reply.data.end(), 4 - Padding(reply), 0);
    }

    hk::Result HandleControl(const Request& request, Response& response, Session& session) {
        switch (request.command) {
        case 0: { // ConvertCurrentObjectToDomain -> object id
            if (session.domain)
                return MakeResult(10, 211);
            session.domain = true;
            const uint32_t id = session.next_id++;
            session.objects[id] = session.object;
            response.Out(id);
            return 0;
        }
        case 2: // CloneCurrentObject
        case 4: // CloneCurrentObjectEx
            if (session.domain) {
                // A domain clones as a whole: a new session with the same objects.
                uint32_t server, client;
                if (handles.size() >= kMaxHandles ||
                    svc::CreateSession(thread, server, client) != hk::result::Success)
                    return MakeResult(10, 3);
                handles.push_back(server);
                sessions[server] = session;
                response.copy.clear();
                cloned_domain = client;
                return 0;
            }
            response.objects.push_back(session.object);
            return 0;
        case 3: // QueryPointerBufferSize
            response.Out(static_cast<uint16_t>(kReceiveSize));
            return 0;
        default: // 1: CopyFromCurrentDomain
            return kUnknownCommand;
        }
    }
};

NativeHost::NativeHost(hk::Kernel& kernel, bool trace) : state_(std::make_unique<State>(kernel, trace)) {}

NativeHost::~NativeHost() {
    // The serving thread still uses the state; keep it for the life of the host.
    if (state_->thread)
        (void)state_.release();
}

void NativeHost::Add(std::string name, uint32_t max_sessions, Factory factory) {
    for (auto& port : state_->ports) {
        if (port.name == name) {
            port = {std::move(name), max_sessions, std::move(factory)};
            return;
        }
    }
    state_->ports.push_back({std::move(name), max_sessions, std::move(factory)});
}

void NativeHost::Omit(const std::vector<std::string>& names) {
    std::erase_if(state_->ports, [&](const State::Port& port) {
        return std::find(names.begin(), names.end(), port.name) != names.end();
    });
}

std::vector<std::string> NativeHost::Names() const {
    std::vector<std::string> names;
    for (const auto& port : state_->ports)
        names.push_back(port.name);
    return names;
}

void NativeHost::Start() {
    state_->process = state_->kernel.CreateProcess(kProcessId, state_->memory);
    state_->thread = state_->kernel.CreateThread(state_->process, kTls);
    state_->host_thread = std::thread([state = state_.get()] { state->Serve(); });
    state_->host_thread.detach();
}

} // namespace services
