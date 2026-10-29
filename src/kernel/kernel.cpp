#include "hk/kernel.h"

#include "hipc.h"
#include "hk/link.h"
#include "platform.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace hk {

namespace detail {

// A kernel object reachable through handles. handle_refs counts handles in
// every process's table, plus references a link holds for its peer; the
// object closes when the last one goes.
struct Object {
    virtual ~Object() = default;
    virtual void LastHandleClosed() {}
    uint32_t handle_refs{};
};

struct ServerPort;
struct Link;

// A session end crossing a link, named by an id the exporting side chose.
enum DescriptorKind : uint32_t { ClientEnd = 1, ServerEnd = 2 };
struct Descriptor {
    uint32_t kind{}, id{};
};

// A message in transit between kernels. Handle slots in words are
// placeholders; descriptors list the copied then moved handles in order.
struct Wire {
    uint64_t pid{};
    std::vector<uint32_t> words;
    std::vector<Descriptor> descriptors;
};

// A request waiting for a server. A local client's request lives on its
// thread's stack; a request from across a link is owned by the kernel.
struct Request {
    std::shared_ptr<Process> process; // local client
    uint64_t tls{};
    Link* link{}; // remote client
    uint64_t tag{};
    Wire wire;
    Result result{};
    bool done{};
};

struct SessionState {
    Kernel::Impl* kernel{};
    bool server_open = true, client_open = true;
    std::deque<Request*> pending;
    Request* current{}; // received by the server, not yet replied to
    std::weak_ptr<ServerPort> port;
    Link* server_link{}; // set when the server end lives across this link
    uint32_t server_id{};
};

struct ServerSession final : Object {
    explicit ServerSession(std::shared_ptr<SessionState> s) : state(std::move(s)) {}
    void LastHandleClosed() override;
    std::shared_ptr<SessionState> state;
};

struct ClientSession final : Object {
    explicit ClientSession(std::shared_ptr<SessionState> s) : state(std::move(s)) {}
    void LastHandleClosed() override;
    std::shared_ptr<SessionState> state;
};

using PortRegistry = std::map<std::string, std::weak_ptr<ServerPort>>;

struct ServerPort final : Object {
    void LastHandleClosed() override;
    Kernel::Impl* kernel{};
    std::string name;
    uint32_t max_sessions{}, sessions{};
    std::deque<std::shared_ptr<ServerSession>> backlog; // connected, not yet accepted
};

// A thread blocked on a reply from across a link.
struct Waiter {
    bool done{};
    Result result{};
    Wire wire;
    uint32_t id{};
};

struct Link {
    Kernel::Impl* kernel{};
    std::unique_ptr<ByteStream> stream;
    uint32_t side{}; // low bit of every id this side allocates
    uint32_t next_id = 1;
    uint64_t next_tag = 1;
    uint32_t AllocateId() { return next_id++ << 1 | side; }

    // Guarded by the kernel lock.
    std::map<uint32_t, std::shared_ptr<ClientSession>> inbound; // our servers, the peer's clients
    std::map<uint32_t, std::weak_ptr<SessionState>> outbound;   // our clients, the peer's servers
    std::map<uint64_t, Waiter*> waiting;
    std::set<std::string> remote_ports;
    bool broken = false;

    // Frames to write; guarded by queue_mutex, drained by the writer thread.
    std::mutex queue_mutex;
    std::condition_variable queue_changed;
    std::deque<std::vector<std::byte>> queue;
    bool stopping = false;

    platform::BlockingThread reader, writer;
};

} // namespace detail

class Process {
public:
    Process(uint64_t process_id, GuestMemory& guest_memory) : id(process_id), memory(guest_memory) {}

    std::shared_ptr<detail::Object> Find(uint32_t handle) const {
        auto it = handles.find(handle);
        return it == handles.end() ? nullptr : it->second;
    }
    template <class T> std::shared_ptr<T> Get(uint32_t handle) const {
        return std::dynamic_pointer_cast<T>(Find(handle));
    }
    uint32_t Add(std::shared_ptr<detail::Object> object) {
        ++object->handle_refs;
        return Attach(std::move(object));
    }
    bool Close(uint32_t handle) {
        auto object = Detach(handle);
        if (!object)
            return false;
        if (--object->handle_refs == 0)
            object->LastHandleClosed();
        return true;
    }
    // Detach and Attach move a handle between tables without closing it.
    std::shared_ptr<detail::Object> Detach(uint32_t handle) {
        auto it = handles.find(handle);
        if (it == handles.end())
            return nullptr;
        auto object = std::move(it->second);
        handles.erase(it);
        return object;
    }
    uint32_t Attach(std::shared_ptr<detail::Object> object) {
        const uint32_t handle = next_handle++;
        handles.emplace(handle, std::move(object));
        return handle;
    }
    void AttachAt(uint32_t handle, std::shared_ptr<detail::Object> object) {
        handles.emplace(handle, std::move(object));
    }

    const uint64_t id;
    GuestMemory& memory;
    std::map<uint32_t, std::shared_ptr<detail::Object>> handles;
    uint32_t next_handle = 0x10;
};

} // namespace hk

struct hk_thread {
    hk::Kernel::Impl* kernel{};
    std::shared_ptr<hk::Process> process;
    uint64_t tls{};
};

namespace hk {

using namespace detail;

namespace {

// Link frames: u32 type, u32 body length, body. Integers are in host byte
// order; both ends of a link run on the same machine.
enum class Frame : uint32_t {
    PortRegistered = 1, // name
    PortUnregistered,   // name
    Connect,            // tag, name
    ConnectReply,       // tag, result, client-end id
    Request,            // server id, tag, message
    Reply,              // tag, result, message
    Close,              // id: the peer closed its client end
    ServerClosed,       // id: the peer closed the server end
};
constexpr uint32_t MaxFrameBytes = 0x10000;
constexpr uint32_t MaxNameBytes = 64;

class FrameWriter {
public:
    explicit FrameWriter(Frame type) {
        U32(static_cast<uint32_t>(type));
        U32(0);
    }
    FrameWriter& U32(uint32_t value) { return Put(&value, sizeof value); }
    FrameWriter& U64(uint64_t value) { return Put(&value, sizeof value); }
    FrameWriter& Text(std::string_view text) {
        U32(static_cast<uint32_t>(text.size()));
        return Put(text.data(), text.size());
    }
    FrameWriter& Message(const Wire& wire) {
        U64(wire.pid);
        U32(static_cast<uint32_t>(wire.words.size()));
        for (const uint32_t word : wire.words)
            U32(word);
        U32(static_cast<uint32_t>(wire.descriptors.size()));
        for (const auto& descriptor : wire.descriptors)
            U32(descriptor.kind).U32(descriptor.id);
        return *this;
    }
    std::vector<std::byte> Finish() {
        const uint32_t length = static_cast<uint32_t>(bytes_.size() - 8);
        std::memcpy(bytes_.data() + 4, &length, sizeof length);
        return std::move(bytes_);
    }

private:
    FrameWriter& Put(const void* data, size_t size) {
        const auto* begin = static_cast<const std::byte*>(data);
        bytes_.insert(bytes_.end(), begin, begin + size);
        return *this;
    }
    std::vector<std::byte> bytes_;
};

class FrameReader {
public:
    explicit FrameReader(std::span<const std::byte> bytes) : bytes_(bytes) {}
    uint32_t U32() {
        uint32_t value{};
        Get(&value, sizeof value);
        return value;
    }
    uint64_t U64() {
        uint64_t value{};
        Get(&value, sizeof value);
        return value;
    }
    std::string Text() {
        const uint32_t size = U32();
        if (size > MaxNameBytes) {
            ok_ = false;
            return {};
        }
        std::string text(size, '\0');
        Get(text.data(), size);
        return text;
    }
    Wire Message() {
        Wire wire;
        wire.pid = U64();
        const uint32_t words = U32();
        if (words > hipc::MessageWords) {
            ok_ = false;
            return wire;
        }
        for (uint32_t i = 0; i < words; ++i)
            wire.words.push_back(U32());
        const uint32_t descriptors = U32();
        if (descriptors > 32) {
            ok_ = false;
            return wire;
        }
        for (uint32_t i = 0; i < descriptors; ++i) {
            Descriptor descriptor;
            descriptor.kind = U32();
            descriptor.id = U32();
            wire.descriptors.push_back(descriptor);
        }
        return wire;
    }
    // True when every read succeeded and the whole body was consumed.
    bool Complete() const { return ok_ && at_ == bytes_.size(); }

private:
    void Get(void* out, size_t size) {
        if (!ok_ || bytes_.size() - at_ < size) {
            ok_ = false;
            std::memset(out, 0, size);
            return;
        }
        std::memcpy(out, bytes_.data() + at_, size);
        at_ += size;
    }
    std::span<const std::byte> bytes_;
    size_t at_{};
    bool ok_ = true;
};

Result ReadName(GuestMemory& memory, uint64_t address, std::string& out) {
    std::array<char, 12> bytes{};
    if (!memory.Read(address, std::as_writable_bytes(std::span(bytes))))
        return result::InvalidPointer;
    auto end = std::find(bytes.begin(), bytes.end(), '\0');
    if (end == bytes.end())
        return result::OutOfRange;
    out.assign(bytes.begin(), end);
    return result::Success;
}

// A message on its way from one place to another, with its handles resolved
// to objects. source is the sending process when the objects came from a
// handle table, or null when they were imported from a link.
struct Envelope {
    std::array<uint32_t, hipc::MessageWords> words{};
    hipc::Layout layout;
    std::vector<std::shared_ptr<Object>> objects; // copied then moved
    std::vector<uint32_t> source_handles;
    Process* source{};
    uint64_t pid{};
};

// Reads and validates a message in a process's buffer. Changes nothing.
Result Collect(Process& from, uint64_t tls, Envelope& envelope) {
    if (!from.memory.Read(tls, std::as_writable_bytes(std::span(envelope.words))))
        return result::InvalidPointer;
    if (const Result r = hipc::Parse(envelope.words, envelope.layout))
        return r;
    const auto& layout = envelope.layout;
    for (uint32_t i = 0; i < layout.copy_count + layout.move_count; ++i) {
        const uint32_t handle = envelope.words[layout.copy_word + i]; // move handles follow copies
        auto object = from.Find(handle);
        if (!object)
            return result::InvalidHandle;
        if (i >= layout.copy_count &&
            std::find(envelope.source_handles.begin() + layout.copy_count, envelope.source_handles.end(), handle) !=
                envelope.source_handles.end())
            return result::InvalidHandle; // the same handle moved twice
        envelope.objects.push_back(std::move(object));
        envelope.source_handles.push_back(handle);
    }
    envelope.source = &from;
    envelope.pid = from.id;
    return result::Success;
}

// Takes moved handles out of the sender once the message will be sent.
void CommitMoves(Envelope& envelope) {
    const auto& layout = envelope.layout;
    for (uint32_t i = layout.copy_count; i < layout.copy_count + layout.move_count; ++i)
        envelope.source->Detach(envelope.source_handles[i]);
}

// Drops a reference that no handle table holds.
void Release(const std::shared_ptr<Object>& object) {
    if (object->handle_refs == 0)
        object->LastHandleClosed();
}

// Places the message and its handles in a process's buffer. On failure the
// receiver is unchanged and moved handles return to the sender (or, for
// imported objects, are released).
Result Deliver(Envelope& envelope, Process& to, uint64_t tls) {
    auto& words = envelope.words;
    const auto& layout = envelope.layout;
    if (layout.send_pid) {
        words[layout.pid_word] = static_cast<uint32_t>(envelope.pid);
        words[layout.pid_word + 1] = static_cast<uint32_t>(envelope.pid >> 32);
    }
    const uint32_t count = layout.copy_count + layout.move_count;
    for (uint32_t i = 0; i < count; ++i) {
        const bool table_move = envelope.source && i >= layout.copy_count;
        words[layout.copy_word + i] =
            table_move ? to.Attach(envelope.objects[i]) : to.Add(envelope.objects[i]);
    }
    if (to.memory.Write(tls, std::as_bytes(std::span(words).first(layout.total_words))))
        return result::Success;

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t handle = words[layout.copy_word + i];
        if (envelope.source && i >= layout.copy_count)
            envelope.source->AttachAt(envelope.source_handles[i], to.Detach(handle));
        else
            to.Close(handle);
    }
    return result::InvalidPointer;
}

Result CopyMessage(Process& from, uint64_t from_tls, Process& to, uint64_t to_tls) {
    Envelope envelope;
    if (const Result r = Collect(from, from_tls, envelope))
        return r;
    CommitMoves(envelope);
    return Deliver(envelope, to, to_tls);
}

} // namespace

struct Kernel::Impl {
    using Lock = std::unique_lock<std::mutex>;

    // ---- Links ----

    void Send(Link& link, std::vector<std::byte> frame) {
        if (link.broken)
            return;
        {
            std::lock_guard queue_lock(link.queue_mutex);
            link.queue.push_back(std::move(frame));
        }
        link.queue_changed.notify_one();
    }

    void Announce(Frame type, const std::string& name) {
        for (auto& link : links)
            Send(*link, FrameWriter(type).Text(name).Finish());
    }

    std::shared_ptr<SessionState> NewState() {
        auto state = std::make_shared<SessionState>();
        state->kernel = this;
        return state;
    }

    // Whether every object in a collected message can cross this link.
    Result CheckExport(const Envelope& envelope) {
        for (size_t i = 0; i < envelope.objects.size(); ++i) {
            const bool move = i >= envelope.layout.copy_count;
            if (auto* client = dynamic_cast<ClientSession*>(envelope.objects[i].get())) {
                if (client->state->server_link)
                    return result::NotImplemented; // forwarding a session that is already remote
            } else if (auto* server = dynamic_cast<ServerSession*>(envelope.objects[i].get())) {
                const auto& state = *server->state;
                if (!move || state.server_link)
                    return result::NotImplemented;
                if (!state.pending.empty() || state.current || HasRemoteClients(state))
                    return result::InvalidState;
            } else {
                return result::NotImplemented; // ports and other objects stay local
            }
        }
        return result::Success;
    }

    bool HasRemoteClients(const SessionState& state) const {
        for (const auto& link : links)
            for (const auto& [id, client] : link->inbound)
                if (client->state.get() == &state)
                    return true;
        return false;
    }

    // Turns a collected (and committed) message into a wire message for link.
    Wire Export(Link& link, Envelope& envelope) {
        Wire wire;
        wire.pid = envelope.pid;
        wire.words.assign(envelope.words.begin(), envelope.words.begin() + envelope.layout.total_words);
        for (size_t i = 0; i < envelope.objects.size(); ++i) {
            const bool move = i >= envelope.layout.copy_count;
            const uint32_t id = link.AllocateId();
            if (auto client = std::dynamic_pointer_cast<ClientSession>(envelope.objects[i])) {
                if (!move)
                    ++client->handle_refs; // a moved handle's reference passes to the link
                link.inbound[id] = std::move(client);
                wire.descriptors.push_back({ClientEnd, id});
            } else {
                auto& state = *std::static_pointer_cast<ServerSession>(envelope.objects[i])->state;
                state.server_link = &link;
                state.server_id = id;
                link.outbound[id] = std::static_pointer_cast<ServerSession>(envelope.objects[i])->state;
                wire.descriptors.push_back({ServerEnd, id});
            }
        }
        return wire;
    }

    std::shared_ptr<Object> Import(Link& link, Descriptor descriptor) {
        if (descriptor.kind == ClientEnd) {
            auto state = NewState();
            state->server_link = &link;
            state->server_id = descriptor.id;
            link.outbound[descriptor.id] = state;
            return std::make_shared<ClientSession>(state);
        }
        if (descriptor.kind == ServerEnd) {
            auto state = NewState();
            auto client = std::make_shared<ClientSession>(state);
            client->handle_refs = 1; // held by the link for the peer's clients
            link.inbound[descriptor.id] = std::move(client);
            return std::make_shared<ServerSession>(state);
        }
        return nullptr;
    }

    Result FromWire(Link& link, const Wire& wire, Envelope& envelope) {
        if (wire.words.size() < 2)
            return result::MessageTooLarge;
        std::copy(wire.words.begin(), wire.words.end(), envelope.words.begin());
        if (const Result r = hipc::Parse(envelope.words, envelope.layout))
            return r;
        const auto& layout = envelope.layout;
        if (layout.total_words != wire.words.size() ||
            wire.descriptors.size() != layout.copy_count + layout.move_count)
            return result::InvalidHandle;
        for (const auto& descriptor : wire.descriptors) {
            auto object = Import(link, descriptor);
            if (!object) {
                for (const auto& imported : envelope.objects)
                    Release(imported);
                envelope.objects.clear();
                return result::InvalidHandle;
            }
            envelope.objects.push_back(std::move(object));
        }
        envelope.source = nullptr;
        envelope.pid = wire.pid;
        return result::Success;
    }

    // Accepts and immediately closes every handle in an undeliverable message,
    // so the sending kernel releases what it exported.
    void DropWire(Link& link, const Wire& wire) {
        Envelope envelope;
        if (FromWire(link, wire, envelope) == result::Success)
            for (const auto& object : envelope.objects)
                Release(object);
    }

    void ReplyToRemote(Request* request, Result result, const Wire& wire = {}) {
        Send(*request->link, FrameWriter(Frame::Reply).U64(request->tag).U32(result).Message(wire).Finish());
        std::erase_if(remote_requests, [&](const auto& owned) { return owned.get() == request; });
    }

    // ---- Closing ----

    void CloseServer(SessionState& state) {
        state.server_open = false;
        for (auto& link : links)
            for (const auto& [id, client] : link->inbound)
                if (client->state.get() == &state)
                    Send(*link, FrameWriter(Frame::ServerClosed).U32(id).Finish());
        if (state.current && state.current->link) {
            ReplyToRemote(state.current, result::SessionClosed);
            state.current = nullptr;
        }
        std::erase_if(state.pending, [&](Request* request) {
            if (!request->link)
                return false; // the local client wakes on server_open
            ReplyToRemote(request, result::SessionClosed);
            return true;
        });
        changed.notify_all();
    }

    void CloseClient(SessionState& state) {
        if (Link* link = state.server_link) {
            Send(*link, FrameWriter(Frame::Close).U32(state.server_id).Finish());
            link->outbound.erase(state.server_id);
        } else {
            state.client_open = false;
            if (auto port = state.port.lock())
                --port->sessions;
        }
        changed.notify_all();
    }

    void ClosePort(ServerPort& port) {
        auto it = ports.find(port.name);
        if (it != ports.end() && it->second.lock().get() == &port) {
            ports.erase(it);
            Announce(Frame::PortUnregistered, port.name);
        }
        for (auto& session : port.backlog)
            CloseServer(*session->state);
        port.backlog.clear();
    }

    void BreakLink(Link& link) {
        if (link.broken)
            return;
        link.broken = true;
        for (auto& [id, weak] : link.outbound)
            if (auto state = weak.lock())
                state->server_open = false;
        auto inbound = std::move(link.inbound);
        link.inbound.clear();
        for (auto& [id, client] : inbound)
            if (--client->handle_refs == 0)
                client->LastHandleClosed();
        link.remote_ports.clear();
        changed.notify_all();
    }

    // ---- Sessions shared by local and remote connects ----

    Result OpenSession(const std::string& name, std::shared_ptr<ClientSession>& out) {
        auto it = ports.find(name);
        auto port = it == ports.end() ? nullptr : it->second.lock();
        if (!port || port->handle_refs == 0)
            return result::NotFound;
        if (port->sessions >= port->max_sessions)
            return result::OutOfSessions;
        auto state = NewState();
        state->port = port;
        port->backlog.push_back(std::make_shared<ServerSession>(state));
        ++port->sessions;
        out = std::make_shared<ClientSession>(state);
        changed.notify_all();
        return result::Success;
    }

    // ---- Incoming frames (reader thread, kernel lock held) ----

    bool Dispatch(Link& link, Frame type, FrameReader& in) {
        switch (type) {
        case Frame::PortRegistered:
        case Frame::PortUnregistered: {
            const std::string name = in.Text();
            if (!in.Complete())
                return false;
            if (type == Frame::PortRegistered)
                link.remote_ports.insert(name);
            else
                link.remote_ports.erase(name);
            return true;
        }
        case Frame::Connect: {
            const uint64_t tag = in.U64();
            const std::string name = in.Text();
            if (!in.Complete())
                return false;
            std::shared_ptr<ClientSession> client;
            const Result r = OpenSession(name, client);
            uint32_t id = 0;
            if (r == result::Success) {
                id = link.AllocateId();
                client->handle_refs = 1;
                link.inbound[id] = std::move(client);
            }
            Send(link, FrameWriter(Frame::ConnectReply).U64(tag).U32(r).U32(id).Finish());
            return true;
        }
        case Frame::ConnectReply: {
            const uint64_t tag = in.U64();
            const Result r = in.U32();
            const uint32_t id = in.U32();
            if (!in.Complete())
                return false;
            auto it = link.waiting.find(tag);
            if (it == link.waiting.end()) {
                if (r == result::Success) // nobody wants the session any more
                    Send(link, FrameWriter(Frame::Close).U32(id).Finish());
                return true;
            }
            it->second->result = r;
            it->second->id = id;
            it->second->done = true;
            link.waiting.erase(it);
            changed.notify_all();
            return true;
        }
        case Frame::Request: {
            const uint32_t id = in.U32();
            const uint64_t tag = in.U64();
            Wire wire = in.Message();
            if (!in.Complete())
                return false;
            auto it = link.inbound.find(id);
            if (it == link.inbound.end() || !it->second->state->server_open) {
                Send(link, FrameWriter(Frame::Reply).U64(tag).U32(result::SessionClosed).Message({}).Finish());
                DropWire(link, wire);
                return true;
            }
            auto request = std::make_unique<Request>();
            request->link = &link;
            request->tag = tag;
            request->wire = std::move(wire);
            it->second->state->pending.push_back(request.get());
            remote_requests.push_back(std::move(request));
            changed.notify_all();
            return true;
        }
        case Frame::Reply: {
            const uint64_t tag = in.U64();
            const Result r = in.U32();
            Wire wire = in.Message();
            if (!in.Complete())
                return false;
            auto it = link.waiting.find(tag);
            if (it == link.waiting.end()) {
                DropWire(link, wire);
                return true;
            }
            it->second->result = r;
            it->second->wire = std::move(wire);
            it->second->done = true;
            link.waiting.erase(it);
            changed.notify_all();
            return true;
        }
        case Frame::Close: {
            const uint32_t id = in.U32();
            if (!in.Complete())
                return false;
            auto it = link.inbound.find(id);
            if (it != link.inbound.end()) {
                auto client = std::move(it->second);
                link.inbound.erase(it);
                if (--client->handle_refs == 0)
                    client->LastHandleClosed();
            }
            return true;
        }
        case Frame::ServerClosed: {
            const uint32_t id = in.U32();
            if (!in.Complete())
                return false;
            auto it = link.outbound.find(id);
            if (it != link.outbound.end())
                if (auto state = it->second.lock())
                    state->server_open = false;
            changed.notify_all();
            return true;
        }
        }
        return false;
    }

    void ReadLoop(Link& link) {
        for (;;) {
            std::array<uint32_t, 2> head{};
            if (!link.stream->Read(std::as_writable_bytes(std::span(head))) || head[1] > MaxFrameBytes)
                break;
            std::vector<std::byte> body(head[1]);
            if (!body.empty() && !link.stream->Read(body))
                break;
            Lock lock(mutex);
            FrameReader reader(body);
            if (!Dispatch(link, static_cast<Frame>(head[0]), reader))
                break; // a malformed frame ends the link
        }
        Lock lock(mutex);
        BreakLink(link);
    }

    void WriteLoop(Link& link) {
        for (;;) {
            std::vector<std::byte> frame;
            {
                std::unique_lock queue_lock(link.queue_mutex);
                link.queue_changed.wait(queue_lock, [&] { return !link.queue.empty() || link.stopping; });
                if (link.queue.empty())
                    return; // stopping, with everything written
                frame = std::move(link.queue.front());
                link.queue.pop_front();
            }
            if (!link.stream->Write(frame))
                return;
        }
    }

    // ---- Supervisor calls ----

    Result CloseHandle(hk_thread& t, hk_regs& r) {
        if (!t.process->Close(static_cast<uint32_t>(r.x[0])))
            return result::InvalidHandle;
        changed.notify_all();
        return result::Success;
    }

    Result ConnectToNamedPort(Lock& lock, hk_thread& t, hk_regs& r) {
        std::string name;
        if (const Result e = ReadName(t.process->memory, r.x[1], name))
            return e;
        std::shared_ptr<ClientSession> client;
        const Result local = OpenSession(name, client);
        if (local == result::Success) {
            r.x[1] = t.process->Add(std::move(client));
            return result::Success;
        }
        if (local != result::NotFound)
            return local;

        auto it = std::find_if(links.begin(), links.end(),
                               [&](const auto& link) { return !link->broken && link->remote_ports.contains(name); });
        if (it == links.end())
            return result::NotFound;
        Link& link = **it;
        Waiter waiter;
        const uint64_t tag = link.next_tag++;
        link.waiting[tag] = &waiter;
        Send(link, FrameWriter(Frame::Connect).U64(tag).Text(name).Finish());
        changed.wait(lock, [&] { return waiter.done || link.broken; });
        if (!waiter.done) {
            link.waiting.erase(tag);
            return result::NotFound;
        }
        if (waiter.result)
            return waiter.result;
        r.x[1] = t.process->Add(Import(link, {ClientEnd, waiter.id}));
        return result::Success;
    }

    Result SendSyncRequest(Lock& lock, hk_thread& t, hk_regs& r) {
        auto client = t.process->Get<ClientSession>(static_cast<uint32_t>(r.x[0]));
        if (!client)
            return result::InvalidHandle;
        auto state = client->state;
        if (!state->server_open)
            return result::SessionClosed;
        if (state->server_link)
            return SendRemote(lock, t, state);

        // Reject what the server could never receive before queueing it.
        Envelope check;
        if (const Result e = Collect(*t.process, t.tls, check))
            return e;
        Request request;
        request.process = t.process;
        request.tls = t.tls;
        state->pending.push_back(&request);
        changed.notify_all();
        changed.wait(lock, [&] { return request.done || !state->server_open; });
        if (!request.done) {
            std::erase(state->pending, &request);
            if (state->current == &request)
                state->current = nullptr;
            return result::SessionClosed;
        }
        return request.result;
    }

    Result SendRemote(Lock& lock, hk_thread& t, const std::shared_ptr<SessionState>& state) {
        Link& link = *state->server_link;
        if (link.broken)
            return result::SessionClosed;
        Envelope envelope;
        if (const Result e = Collect(*t.process, t.tls, envelope))
            return e;
        if (const Result e = CheckExport(envelope))
            return e;
        CommitMoves(envelope);
        const Wire wire = Export(link, envelope);

        Waiter waiter;
        const uint64_t tag = link.next_tag++;
        link.waiting[tag] = &waiter;
        Send(link, FrameWriter(Frame::Request).U32(state->server_id).U64(tag).Message(wire).Finish());
        changed.wait(lock, [&] { return waiter.done || !state->server_open || link.broken; });
        if (!waiter.done) {
            link.waiting.erase(tag);
            return result::SessionClosed;
        }
        if (waiter.result)
            return waiter.result;
        Envelope reply;
        if (const Result e = FromWire(link, waiter.wire, reply))
            return e;
        return Deliver(reply, *t.process, t.tls);
    }

    Result CreateSession(hk_thread& t, hk_regs& r) {
        if (r.x[2] != 0)
            return result::NotImplemented; // light sessions
        auto state = NewState();
        r.x[1] = t.process->Add(std::make_shared<ServerSession>(state));
        r.x[2] = t.process->Add(std::make_shared<ClientSession>(state));
        return result::Success;
    }

    Result AcceptSession(hk_thread& t, hk_regs& r) {
        auto port = t.process->Get<ServerPort>(static_cast<uint32_t>(r.x[1]));
        if (!port)
            return result::InvalidHandle;
        if (port->backlog.empty())
            return result::NotFound;
        auto session = std::move(port->backlog.front());
        port->backlog.pop_front();
        r.x[1] = t.process->Add(std::move(session));
        return result::Success;
    }

    Result Reply(hk_thread& t, uint32_t reply_target) {
        auto server = t.process->Get<ServerSession>(reply_target);
        if (!server)
            return result::InvalidHandle;
        Request* request = server->state->current;
        if (!request)
            return result::InvalidState;
        server->state->current = nullptr;

        if (Link* link = request->link) {
            Envelope envelope;
            Result r = Collect(*t.process, t.tls, envelope);
            if (r == result::Success)
                r = CheckExport(envelope);
            if (r != result::Success) {
                ReplyToRemote(request, result::SessionClosed);
                return r;
            }
            CommitMoves(envelope);
            const Wire wire = Export(*link, envelope);
            ReplyToRemote(request, result::Success, wire);
            return result::Success;
        }

        const Result copied = CopyMessage(*t.process, t.tls, *request->process, request->tls);
        // A reply that cannot be delivered ends the client's call as a closed session.
        request->result = copied ? result::SessionClosed : result::Success;
        request->done = true;
        changed.notify_all();
        return copied;
    }

    // Moves the next deliverable request of a session into the server's buffer.
    bool Receive(hk_thread& t, SessionState& state) {
        while (!state.pending.empty()) {
            Request* request = state.pending.front();
            state.pending.pop_front();
            Result r;
            if (request->link) {
                Envelope envelope;
                r = FromWire(*request->link, request->wire, envelope);
                if (r == result::Success)
                    r = Deliver(envelope, *t.process, t.tls);
                if (r != result::Success) {
                    ReplyToRemote(request, r);
                    continue;
                }
            } else {
                r = CopyMessage(*request->process, request->tls, *t.process, t.tls);
                if (r != result::Success) {
                    request->result = r;
                    request->done = true;
                    changed.notify_all();
                    continue;
                }
            }
            state.current = request;
            return true;
        }
        return false;
    }

    Result ReplyAndReceive(Lock& lock, hk_thread& t, hk_regs& r) {
        const uint32_t count = static_cast<uint32_t>(r.x[2]);
        if (count > 0x40)
            return result::OutOfRange;
        std::vector<uint32_t> handles(count);
        if (count && !t.process->memory.Read(r.x[1], std::as_writable_bytes(std::span(handles))))
            return result::InvalidPointer;
        if (const uint32_t reply_target = static_cast<uint32_t>(r.x[3]))
            if (const Result e = Reply(t, reply_target))
                return e;

        const auto timeout = static_cast<int64_t>(r.x[4]);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::nanoseconds(std::max<int64_t>(timeout, 0));
        for (;;) {
            for (uint32_t i = 0; i < count; ++i) {
                auto object = t.process->Find(handles[i]);
                r.x[1] = i;
                if (auto* port = dynamic_cast<ServerPort*>(object.get())) {
                    if (!port->backlog.empty())
                        return result::Success;
                } else if (auto* server = dynamic_cast<ServerSession*>(object.get())) {
                    auto& state = *server->state;
                    if (state.current)
                        continue;
                    if (Receive(t, state))
                        return result::Success;
                    if (!state.client_open)
                        return result::SessionClosed;
                } else {
                    return result::InvalidHandle; // other waitables are not implemented
                }
            }
            if (timeout >= 0 && std::chrono::steady_clock::now() >= deadline)
                return result::TimedOut;
            if (timeout < 0)
                changed.wait(lock);
            else
                changed.wait_until(lock, deadline);
        }
    }

    Result ManageNamedPort(hk_thread& t, hk_regs& r) {
        std::string name;
        if (const Result e = ReadName(t.process->memory, r.x[1], name))
            return e;
        const uint32_t max_sessions = static_cast<uint32_t>(r.x[2]);
        auto it = ports.find(name);
        const bool registered = it != ports.end() && !it->second.expired();
        if (max_sessions == 0) {
            if (!registered)
                return result::NotFound;
            ports.erase(it);
            Announce(Frame::PortUnregistered, name);
            return result::Success;
        }
        if (registered)
            return result::InvalidState;
        auto port = std::make_shared<ServerPort>();
        port->kernel = this;
        port->name = name;
        port->max_sessions = max_sessions;
        ports[name] = port;
        Announce(Frame::PortRegistered, name);
        r.x[1] = t.process->Add(std::move(port));
        return result::Success;
    }

    // ---- Lifetime ----

    void Shutdown() {
        std::vector<Link*> all;
        {
            Lock lock(mutex);
            for (auto& link : links)
                all.push_back(link.get());
        }
        for (Link* link : all) {
            {
                std::lock_guard queue_lock(link->queue_mutex);
                link->stopping = true;
            }
            link->queue_changed.notify_all();
            link->writer.Stop(); // drains queued frames first
            link->reader.Stop();
        }
    }

    std::mutex mutex;
    std::condition_variable changed;
    PortRegistry ports;
    std::vector<std::unique_ptr<hk_thread>> threads;
    std::vector<std::unique_ptr<Link>> links;
    std::vector<std::unique_ptr<Request>> remote_requests;
};

namespace detail {

void ServerSession::LastHandleClosed() { state->kernel->CloseServer(*state); }
void ClientSession::LastHandleClosed() { state->kernel->CloseClient(*state); }
void ServerPort::LastHandleClosed() { kernel->ClosePort(*this); }

} // namespace detail

Kernel::Kernel() : impl_(std::make_unique<Impl>()) {}

Kernel::~Kernel() { impl_->Shutdown(); }

std::shared_ptr<Process> Kernel::CreateProcess(uint64_t process_id, GuestMemory& memory) {
    return std::make_shared<Process>(process_id, memory);
}

hk_thread* Kernel::CreateThread(const std::shared_ptr<Process>& process, uint64_t tls_address) {
    std::lock_guard lock(impl_->mutex);
    auto thread = std::make_unique<hk_thread>(hk_thread{impl_.get(), process, tls_address});
    return impl_->threads.emplace_back(std::move(thread)).get();
}

void Kernel::DestroyThread(hk_thread* thread) {
    std::lock_guard lock(impl_->mutex);
    std::erase_if(impl_->threads, [&](const auto& owned) { return owned.get() == thread; });
}

void Kernel::DestroyProcess(const std::shared_ptr<Process>& process) {
    std::lock_guard lock(impl_->mutex);
    while (!process->handles.empty())
        process->Close(process->handles.begin()->first);
    impl_->changed.notify_all();
}

void Kernel::AttachLink(std::unique_ptr<ByteStream> stream, bool initiator) {
    Link* link;
    {
        std::lock_guard lock(impl_->mutex);
        auto owned = std::make_unique<Link>();
        owned->kernel = impl_.get();
        owned->stream = std::move(stream);
        owned->side = initiator ? 0 : 1;
        link = impl_->links.emplace_back(std::move(owned)).get();
        for (const auto& [name, port] : impl_->ports)
            if (!port.expired())
                impl_->Send(*link, FrameWriter(Frame::PortRegistered).Text(name).Finish());
    }
    link->writer.Start([this, link] { impl_->WriteLoop(*link); });
    link->reader.Start([this, link] { impl_->ReadLoop(*link); });
}

size_t Kernel::HandleCount(const std::shared_ptr<Process>& process) const {
    std::lock_guard lock(impl_->mutex);
    return process->handles.size();
}

} // namespace hk

extern "C" void hk_svc(hk_thread* thread, uint32_t id, hk_regs* regs) {
    auto& kernel = *thread->kernel;
    hk::Kernel::Impl::Lock lock(kernel.mutex);
    hk::Result result;
    switch (id) {
    case HK_SVC_CLOSE_HANDLE: result = kernel.CloseHandle(*thread, *regs); break;
    case HK_SVC_CONNECT_TO_NAMED_PORT: result = kernel.ConnectToNamedPort(lock, *thread, *regs); break;
    case HK_SVC_SEND_SYNC_REQUEST: result = kernel.SendSyncRequest(lock, *thread, *regs); break;
    case HK_SVC_CREATE_SESSION: result = kernel.CreateSession(*thread, *regs); break;
    case HK_SVC_ACCEPT_SESSION: result = kernel.AcceptSession(*thread, *regs); break;
    case HK_SVC_REPLY_AND_RECEIVE: result = kernel.ReplyAndReceive(lock, *thread, *regs); break;
    case HK_SVC_MANAGE_NAMED_PORT: result = kernel.ManageNamedPort(*thread, *regs); break;
    default: result = hk::result::NotImplemented; break;
    }
    regs->x[0] = result;
}
