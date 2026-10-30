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
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <utility>
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

// An object crossing a link, named by an id the exporting side chose: a
// session end, or a readable event with its signal state at that moment. A
// process crosses as its id alone (in generation).
enum DescriptorKind : uint32_t { ClientEnd = 1, ServerEnd = 2, EventEnd = 3, ProcessEnd = 4 };
struct Descriptor {
    uint32_t kind{}, id{};
    uint32_t signaled{};
    uint64_t generation{};
};

// A buffer a message carries, with the sender's bytes. ordinal counts X
// buffers for Static, and A, B and W together for the others. A Writeback
// travels in a reply across a link: the server's final contents of the B or
// W buffer with that ordinal.
enum BufferKind : uint32_t { BufferStatic, BufferSend, BufferReceive, BufferExchange, BufferWriteback };
struct Buffer {
    uint32_t kind{}, ordinal{};
    uint64_t address{}, size{};
    std::vector<std::byte> data;
};

// An A, B or W buffer mapped into a server for the request it is serving.
struct Mapping {
    uint32_t kind{}, ordinal{};
    uint64_t address{}, size{}; // in the server
    uint64_t client_address{};  // in a local client
};

// A message in transit between kernels. Handle slots in words are
// placeholders; descriptors list the copied then moved handles in order.
struct Wire {
    uint64_t pid{};
    std::vector<uint32_t> words;
    std::vector<Descriptor> descriptors;
    std::vector<Buffer> buffers;
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
    std::vector<Mapping> mappings; // in the server, while it serves this request
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

// A thread's handle-visible side: signalled once the thread has exited.
struct ThreadObject final : Object {
    hk_thread* thread{}; // null once exited
    uint64_t id{};
};

// A handle to a process, as a copied current-process pseudo-handle gives a
// server (am, for one, receives the application's).
struct ProcessObject final : Object {
    uint64_t id{};
};

// An event lives in one kernel. A readable end copied or moved across a link
// becomes a mirror in the other kernel: the owner sends every change of the
// signal state, and a mirror's clears go back to the owner. generation counts
// signals, so the owner ignores a clear that a newer signal overtook.
struct EventState {
    bool signaled{};
    uint64_t generation{};
    std::vector<std::pair<Link*, uint32_t>> exports; // the owner's mirrors
    Link* owner_link{};                              // set on a mirror
    uint32_t owner_id{};
    std::map<uint64_t, std::function<void(bool)>> watchers; // Kernel::WatchEvent
};

struct ReadableEvent final : Object {
    void LastHandleClosed() override;
    Kernel::Impl* kernel{};
    std::shared_ptr<EventState> state;
};

struct WritableEvent final : Object {
    std::shared_ptr<EventState> state;
};

struct SharedMemory final : Object {
    std::vector<std::byte> contents;
};

// A range of its creator's memory that a process lends to a server, which
// works on it in place. It stays in this kernel: a link does not carry it.
struct TransferMemory final : Object {
    GuestMemory* memory{};
    uint64_t address{}, size{};
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
    std::map<uint32_t, std::shared_ptr<ReadableEvent>> exported_events; // ours, mirrored by the peer
    std::map<uint32_t, std::shared_ptr<EventState>> mirrored_events;    // the peer's, from arrival to last close
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
    Process(uint64_t process_id, GuestMemory& guest_memory) : id(process_id), memory(guest_memory) {
        self->id = process_id;
    }

    std::shared_ptr<detail::Object> Find(uint32_t handle) const {
        if (handle == static_cast<uint32_t>(HK_CURRENT_PROCESS))
            return self;
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
    const std::shared_ptr<detail::ProcessObject> self = std::make_shared<detail::ProcessObject>();
    std::map<uint32_t, std::shared_ptr<detail::Object>> handles;
    uint32_t next_handle = 0x10;
};

} // namespace hk

struct hk_thread {
    hk::Kernel::Impl* kernel{};
    std::shared_ptr<hk::Process> process;
    uint64_t tls{};
    std::shared_ptr<hk::detail::ThreadObject> object;
    void* user{};
    bool cancel_pending{};

    // Address arbiter state, guarded by the kernel lock. A thread waits
    // either for a guest mutex (lock_owner set) or on a condition variable
    // key; woken and wake_result report how the wait ended.
    enum class Wait { None, Mutex, CondVar } wait{};
    uint64_t mutex_address{};
    uint64_t cv_key{};
    uint32_t tag{};
    hk_thread* lock_owner{};
    bool woken{};
    hk::Result wake_result{};
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
    EventChanged,       // id, signaled, generation: an exported event's new state
    EventCleared,       // id, generation: a mirror was cleared
    EventClosed,        // id: the last handle to a mirror closed
};
constexpr uint32_t MaxBufferBytes = 64u << 20; // per message, all buffers together
constexpr uint32_t MaxFrameBytes = MaxBufferBytes + 0x10000;
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
            U32(descriptor.kind).U32(descriptor.id).U32(descriptor.signaled).U64(descriptor.generation);
        U32(static_cast<uint32_t>(wire.buffers.size()));
        for (const auto& buffer : wire.buffers) {
            U32(buffer.kind).U32(buffer.ordinal).U64(buffer.address).U64(buffer.size);
            U32(static_cast<uint32_t>(buffer.data.size()));
            Put(buffer.data.data(), buffer.data.size());
        }
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
            descriptor.signaled = U32();
            descriptor.generation = U64();
            wire.descriptors.push_back(descriptor);
        }
        const uint32_t buffers = U32();
        if (buffers > 64) {
            ok_ = false;
            return wire;
        }
        for (uint32_t i = 0; i < buffers && ok_; ++i) {
            Buffer buffer;
            buffer.kind = U32();
            buffer.ordinal = U32();
            buffer.address = U64();
            buffer.size = U64();
            const uint32_t bytes = U32();
            if (bytes > MaxBufferBytes || bytes_.size() - at_ < bytes) {
                ok_ = false;
                return wire;
            }
            buffer.data.resize(bytes);
            Get(buffer.data.data(), bytes);
            wire.buffers.push_back(std::move(buffer));
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
    std::vector<Buffer> buffers; // X in order, then A, B and W in order
    Process* source{};
    uint64_t pid{};
};

// Reads the buffers a parsed message describes from the sender's memory.
Result CollectBuffers(Process& from, Envelope& envelope) {
    const auto& layout = envelope.layout;
    uint64_t total = 0;
    auto read = [&](Buffer& buffer) {
        total += buffer.size;
        if (total > MaxBufferBytes)
            return result::MessageTooLarge;
        buffer.data.resize(buffer.size);
        if (buffer.size && !from.memory.Read(buffer.address, buffer.data))
            return result::InvalidPointer;
        return result::Success;
    };
    for (uint32_t i = 0; i < layout.static_count; ++i) {
        const auto d = hipc::DecodeStatic(&envelope.words[layout.static_word + 2 * i]);
        Buffer buffer{BufferStatic, i, d.address, d.size, {}};
        if (const Result r = read(buffer))
            return r;
        envelope.buffers.push_back(std::move(buffer));
    }
    for (uint32_t i = 0; i < layout.buffer_count(); ++i) {
        const auto d = hipc::DecodeBuffer(&envelope.words[layout.buffer_word + 3 * i]);
        const uint32_t kind = i < layout.send_count ? BufferSend
                              : i < layout.send_count + layout.receive_count ? BufferReceive
                                                                             : BufferExchange;
        // B is read too: the server sees the client's memory, and bytes it
        // does not write must come back unchanged.
        Buffer buffer{kind, i, d.address, d.address ? d.size : 0, {}};
        if (const Result r = read(buffer))
            return r;
        envelope.buffers.push_back(std::move(buffer));
    }
    return result::Success;
}

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
            (handle == static_cast<uint32_t>(HK_CURRENT_PROCESS) ||
             std::find(envelope.source_handles.begin() + layout.copy_count, envelope.source_handles.end(), handle) !=
                 envelope.source_handles.end()))
            return result::InvalidHandle; // a pseudo-handle or the same handle moved
        envelope.objects.push_back(std::move(object));
        envelope.source_handles.push_back(handle);
    }
    if (const Result r = CollectBuffers(from, envelope))
        return r;
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

// Undoes CommitMoves for a message that will not be delivered: moved
// handles return to the sender; imported objects are released.
void ReturnHandles(Envelope& envelope) {
    const auto& layout = envelope.layout;
    for (uint32_t i = 0; i < layout.copy_count + layout.move_count; ++i) {
        if (!envelope.source)
            Release(envelope.objects[i]);
        else if (i >= layout.copy_count)
            envelope.source->AttachAt(envelope.source_handles[i], envelope.objects[i]);
    }
}

void Unmap(Process& process, std::vector<Mapping>& mappings) {
    for (const auto& mapping : mappings)
        process.memory.UnmapIpcBuffer(mapping.address, mapping.size);
    mappings.clear();
}

// Copies X buffers into the receive list the receiver left in its message
// buffer, and maps A, B and W buffers (requests only: mappings is null for a
// reply, which may not carry them). Rewrites the descriptors with the
// receiver's addresses.
Result PlaceBuffers(Envelope& envelope, Process& to, uint64_t tls, std::vector<Mapping>* mappings) {
    auto& words = envelope.words;
    const auto& layout = envelope.layout;
    if (layout.static_count) {
        std::array<uint32_t, hipc::MessageWords> current{};
        hipc::Layout receiver;
        if (!to.memory.Read(tls, std::as_writable_bytes(std::span(current))))
            return result::InvalidPointer;
        if (hipc::Parse(current, receiver) != result::Success || receiver.receive_list_count == 0)
            return result::ReceiveListBroken;
        uint64_t packed = 0; // used bytes of a single receive buffer
        for (uint32_t i = 0; i < layout.static_count; ++i) {
            const Buffer& buffer = envelope.buffers[i];
            auto d = hipc::DecodeStatic(&words[layout.static_word + 2 * i]);
            uint64_t address = 0;
            if (receiver.receive_list_single) {
                const auto entry = hipc::DecodeReceive(&current[receiver.receive_list_word]);
                packed = (packed + 15) & ~uint64_t{15};
                if (packed + buffer.size > entry.size)
                    return result::ReceiveListBroken;
                address = entry.address + packed;
                packed += buffer.size;
            } else {
                if (d.index >= receiver.receive_list_count)
                    return result::ReceiveListBroken;
                const auto entry = hipc::DecodeReceive(&current[receiver.receive_list_word + 2 * d.index]);
                if (buffer.size > entry.size)
                    return result::ReceiveListBroken;
                address = entry.address;
            }
            if (buffer.size && !to.memory.Write(address, buffer.data))
                return result::ReceiveListBroken;
            d.address = buffer.size ? address : 0;
            hipc::EncodeStatic(d, &words[layout.static_word + 2 * i]);
        }
    }
    if (layout.buffer_count() && !mappings)
        return result::NotImplemented; // A, B and W in a reply
    for (uint32_t i = 0; i < layout.buffer_count(); ++i) {
        const Buffer& buffer = envelope.buffers[layout.static_count + i];
        auto d = hipc::DecodeBuffer(&words[layout.buffer_word + 3 * i]);
        if (buffer.size == 0) {
            d.address = 0;
        } else {
            uint64_t address;
            if (!to.memory.MapIpcBuffer(buffer.size, address)) {
                Unmap(to, *mappings);
                return result::OutOfMemory;
            }
            mappings->push_back({buffer.kind, buffer.ordinal, address, buffer.size, buffer.address});
            if (!to.memory.Write(address, buffer.data)) {
                Unmap(to, *mappings);
                return result::OutOfMemory;
            }
            d.address = address;
        }
        hipc::EncodeBuffer(d, &words[layout.buffer_word + 3 * i]);
    }
    return result::Success;
}

// The server's final B and W contents, for copying back to the client.
std::vector<Buffer> TakeWritebacks(Process& server, std::vector<Mapping>& mappings) {
    std::vector<Buffer> out;
    for (const auto& mapping : mappings) {
        if (mapping.kind != BufferReceive && mapping.kind != BufferExchange)
            continue;
        Buffer buffer{BufferWriteback, mapping.ordinal, mapping.client_address, mapping.size, {}};
        buffer.data.resize(mapping.size);
        if (server.memory.Read(mapping.address, buffer.data))
            out.push_back(std::move(buffer));
    }
    Unmap(server, mappings);
    return out;
}

// Places the message and its handles in a process's buffer. On failure
// moved handles return to the sender (or, for imported objects, are
// released) and no buffer stays mapped; X bytes already copied into the
// receiver's receive list may remain.
Result Deliver(Envelope& envelope, Process& to, uint64_t tls, std::vector<Mapping>* mappings = nullptr) {
    auto& words = envelope.words;
    const auto& layout = envelope.layout;
    if (const Result r = PlaceBuffers(envelope, to, tls, mappings)) {
        ReturnHandles(envelope);
        return r;
    }
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
    if (mappings)
        Unmap(to, *mappings);

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t handle = words[layout.copy_word + i];
        if (envelope.source && i >= layout.copy_count)
            envelope.source->AttachAt(envelope.source_handles[i], to.Detach(handle));
        else
            to.Close(handle);
    }
    return result::InvalidPointer;
}

Result CopyMessage(Process& from, uint64_t from_tls, Process& to, uint64_t to_tls,
                   std::vector<Mapping>* mappings = nullptr) {
    Envelope envelope;
    if (const Result r = Collect(from, from_tls, envelope))
        return r;
    CommitMoves(envelope);
    return Deliver(envelope, to, to_tls, mappings);
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
            } else if (auto* event = dynamic_cast<ReadableEvent*>(envelope.objects[i].get())) {
                if (event->state->owner_link)
                    return result::NotImplemented; // forwarding a mirror
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
        wire.buffers = envelope.buffers;
        for (size_t i = 0; i < envelope.objects.size(); ++i) {
            const bool move = i >= envelope.layout.copy_count;
            const uint32_t id = link.AllocateId();
            if (auto client = std::dynamic_pointer_cast<ClientSession>(envelope.objects[i])) {
                if (!move)
                    ++client->handle_refs; // a moved handle's reference passes to the link
                link.inbound[id] = std::move(client);
                wire.descriptors.push_back({ClientEnd, id});
            } else if (auto event = std::dynamic_pointer_cast<ReadableEvent>(envelope.objects[i])) {
                if (!move)
                    ++event->handle_refs; // as for a client end
                auto& state = *event->state;
                state.exports.emplace_back(&link, id);
                wire.descriptors.push_back({EventEnd, id, state.signaled, state.generation});
                link.exported_events[id] = std::move(event);
            } else if (auto process = std::dynamic_pointer_cast<ProcessObject>(envelope.objects[i])) {
                wire.descriptors.push_back({ProcessEnd, id, 0, process->id});
            } else if (!std::dynamic_pointer_cast<ServerSession>(envelope.objects[i])) {
                wire.descriptors.push_back({0, id}); // nothing the other kernel can hold
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
        if (descriptor.kind == EventEnd) {
            auto it = link.mirrored_events.find(descriptor.id);
            if (it == link.mirrored_events.end())
                return nullptr;
            auto event = std::make_shared<ReadableEvent>();
            event->kernel = this;
            event->state = it->second;
            return event;
        }
        if (descriptor.kind == ProcessEnd) {
            auto process = std::make_shared<ProcessObject>();
            process->id = descriptor.generation;
            return process;
        }
        return nullptr;
    }

    // Creates the mirrors for the events in a message as it arrives, so that
    // changes sent after it apply even before the message is delivered.
    void AddMirrors(Link& link, const Wire& wire) {
        for (const auto& descriptor : wire.descriptors) {
            if (descriptor.kind != EventEnd || link.mirrored_events.contains(descriptor.id))
                continue;
            auto state = std::make_shared<EventState>();
            state->signaled = descriptor.signaled != 0;
            state->generation = descriptor.generation;
            state->owner_link = &link;
            state->owner_id = descriptor.id;
            link.mirrored_events[descriptor.id] = std::move(state);
        }
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
        for (const auto& buffer : wire.buffers)
            if (buffer.kind != BufferWriteback)
                envelope.buffers.push_back(buffer);
        if (envelope.buffers.size() != layout.static_count + layout.buffer_count())
            return result::InvalidPointer;
        for (const auto& buffer : envelope.buffers)
            if (buffer.data.size() != buffer.size)
                return result::InvalidPointer;
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

    // ---- Events ----

    // Tells the event's mirrors its state, and its watchers and waiters too
    // if the state changed from was.
    void EventChanged(EventState& state, bool was) {
        for (const auto& [link, id] : state.exports)
            Send(*link, FrameWriter(Frame::EventChanged).U32(id).U32(state.signaled).U64(state.generation).Finish());
        if (state.signaled == was)
            return;
        for (const auto& [token, watch] : state.watchers)
            watch(state.signaled);
        changed.notify_all();
    }

    void SignalState(EventState& state) {
        const bool was = std::exchange(state.signaled, true);
        ++state.generation;
        EventChanged(state, was);
    }

    void ClearState(EventState& state) {
        const bool was = std::exchange(state.signaled, false);
        if (state.owner_link)
            Send(*state.owner_link, FrameWriter(Frame::EventCleared).U32(state.owner_id).U64(state.generation).Finish());
        EventChanged(state, was);
    }

    void CloseEvent(ReadableEvent& event) {
        auto& state = *event.state;
        if (Link* link = state.owner_link) {
            Send(*link, FrameWriter(Frame::EventClosed).U32(state.owner_id).Finish());
            link->mirrored_events.erase(state.owner_id);
        }
    }

    // Drops the reference a link held for an event the peer mirrored.
    void ReleaseExport(Link& link, const std::shared_ptr<ReadableEvent>& event, uint32_t id) {
        std::erase(event->state->exports, std::pair{&link, id});
        if (--event->handle_refs == 0)
            event->LastHandleClosed();
    }

    void BreakLink(Link& link) {
        if (link.broken)
            return;
        link.broken = true;
        auto exported = std::move(link.exported_events);
        link.exported_events.clear();
        for (auto& [id, event] : exported)
            ReleaseExport(link, event, id);
        link.mirrored_events.clear(); // mirrors keep their last state
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
            AddMirrors(link, wire);
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
            AddMirrors(link, wire);
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
        case Frame::EventChanged: {
            const uint32_t id = in.U32();
            const bool signaled = in.U32() != 0;
            const uint64_t generation = in.U64();
            if (!in.Complete())
                return false;
            auto it = link.mirrored_events.find(id);
            if (it != link.mirrored_events.end()) { // else the mirror closed meanwhile
                const bool was = std::exchange(it->second->signaled, signaled);
                it->second->generation = generation;
                EventChanged(*it->second, was);
            }
            return true;
        }
        case Frame::EventCleared: {
            const uint32_t id = in.U32();
            const uint64_t generation = in.U64();
            if (!in.Complete())
                return false;
            auto it = link.exported_events.find(id);
            if (it == link.exported_events.end())
                return true;
            auto& state = *it->second->state;
            // A signal after the one the mirror saw stands.
            if (state.signaled && state.generation == generation) {
                state.signaled = false;
                EventChanged(state, true);
            }
            return true;
        }
        case Frame::EventClosed: {
            const uint32_t id = in.U32();
            if (!in.Complete())
                return false;
            auto it = link.exported_events.find(id);
            if (it != link.exported_events.end()) {
                auto event = std::move(it->second);
                link.exported_events.erase(it);
                ReleaseExport(link, event, id);
            }
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
        for (const auto& writeback : waiter.wire.buffers) {
            if (writeback.kind != BufferWriteback)
                continue;
            const auto it = std::find_if(envelope.buffers.begin(), envelope.buffers.end(), [&](const Buffer& b) {
                return (b.kind == BufferReceive || b.kind == BufferExchange) && b.ordinal == writeback.ordinal;
            });
            if (it != envelope.buffers.end() && it->size == writeback.data.size())
                t.process->memory.Write(it->address, writeback.data);
        }
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

        std::vector<Buffer> writebacks = TakeWritebacks(*t.process, request->mappings);
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
            Wire wire = Export(*link, envelope);
            for (auto& writeback : writebacks)
                wire.buffers.push_back(std::move(writeback));
            ReplyToRemote(request, result::Success, wire);
            return result::Success;
        }

        for (const auto& writeback : writebacks)
            request->process->memory.Write(writeback.address, writeback.data);
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
                    r = Deliver(envelope, *t.process, t.tls, &request->mappings);
                if (r != result::Success) {
                    ReplyToRemote(request, r);
                    continue;
                }
            } else {
                r = CopyMessage(*request->process, request->tls, *t.process, t.tls, &request->mappings);
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
            if (t.cancel_pending) {
                t.cancel_pending = false;
                return result::Cancelled;
            }
            for (uint32_t i = 0; i < count; ++i) {
                auto object = t.process->Find(handles[i]);
                r.x[1] = i;
                if (dynamic_cast<ReadableEvent*>(object.get()) || dynamic_cast<ThreadObject*>(object.get())) {
                    if (IsSignaled(object.get()))
                        return result::Success;
                } else if (auto* port = dynamic_cast<ServerPort*>(object.get())) {
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
                    return result::InvalidHandle;
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

    // ---- Synchronization ----

    static constexpr uint32_t kHasWaiters = 0x40000000;

    hk_thread* ThreadFromHandle(hk_thread& t, uint32_t handle) {
        if (handle == HK_CURRENT_THREAD)
            return &t;
        auto object = t.process->Get<ThreadObject>(handle);
        return object ? object->thread : nullptr;
    }

    // Whether WaitSynchronization would return for this object now.
    static bool IsSignaled(Object* object) {
        if (auto* event = dynamic_cast<ReadableEvent*>(object))
            return event->state->signaled;
        if (auto* thread = dynamic_cast<ThreadObject*>(object))
            return thread->thread == nullptr;
        if (auto* port = dynamic_cast<ServerPort*>(object))
            return !port->backlog.empty();
        if (auto* server = dynamic_cast<ServerSession*>(object)) {
            const auto& state = *server->state;
            return !state.client_open || (!state.current && !state.pending.empty());
        }
        return false;
    }

    static bool IsWaitable(Object* object) {
        return dynamic_cast<ReadableEvent*>(object) || dynamic_cast<ThreadObject*>(object) ||
               dynamic_cast<ServerPort*>(object) || dynamic_cast<ServerSession*>(object);
    }

    Result WaitSynchronization(Lock& lock, hk_thread& t, hk_regs& r) {
        const uint32_t count = static_cast<uint32_t>(r.x[2]);
        if (count > 0x40)
            return result::OutOfRange;
        std::vector<uint32_t> handles(count);
        if (count && !t.process->memory.Read(r.x[1], std::as_writable_bytes(std::span(handles))))
            return result::InvalidPointer;
        std::vector<std::shared_ptr<Object>> objects;
        for (uint32_t handle : handles) {
            std::shared_ptr<Object> object =
                handle == HK_CURRENT_THREAD ? std::shared_ptr<Object>(t.object) : t.process->Find(handle);
            if (!object || !IsWaitable(object.get()))
                return result::InvalidHandle;
            objects.push_back(std::move(object));
        }
        const auto timeout = static_cast<int64_t>(r.x[3]);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::nanoseconds(std::max<int64_t>(timeout, 0));
        for (;;) {
            if (t.cancel_pending) {
                t.cancel_pending = false;
                return result::Cancelled;
            }
            for (uint32_t i = 0; i < count; ++i) {
                if (IsSignaled(objects[i].get())) {
                    r.x[1] = i;
                    return result::Success;
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

    Result CancelSynchronization(hk_thread& t, hk_regs& r) {
        hk_thread* target = ThreadFromHandle(t, static_cast<uint32_t>(r.x[0]));
        if (!target)
            return result::InvalidHandle;
        target->cancel_pending = true;
        changed.notify_all();
        return result::Success;
    }

    Result CreateSharedMemory(hk_thread& t, hk_regs& r) {
        const uint64_t size = r.x[1];
        if (size == 0 || size % 0x1000 || size > (64u << 20))
            return result::OutOfRange;
        auto memory = std::make_shared<SharedMemory>();
        memory->contents.resize(size);
        r.x[1] = t.process->Add(std::move(memory));
        return result::Success;
    }

    // MapSharedMemory(handle, address, size, permission): a copy of the
    // contents at this moment.
    Result MapSharedMemory(hk_thread& t, hk_regs& r) {
        auto memory = t.process->Get<SharedMemory>(static_cast<uint32_t>(r.x[0]));
        if (!memory)
            return result::InvalidHandle;
        const uint64_t address = r.x[1], size = r.x[2];
        if (address % 0x1000 || size != memory->contents.size())
            return result::InvalidAddress;
        if (!t.process->memory.MapAt(address, size))
            return result::InvalidCurrentMemory;
        t.process->memory.Write(address, memory->contents);
        return result::Success;
    }

    Result UnmapSharedMemory(hk_thread& t, hk_regs& r) {
        auto memory = t.process->Get<SharedMemory>(static_cast<uint32_t>(r.x[0]));
        if (!memory)
            return result::InvalidHandle;
        t.process->memory.UnmapAt(r.x[1], r.x[2]);
        return result::Success;
    }

    // CreateTransferMemory(address, size, permission) -> handle
    Result CreateTransferMemory(hk_thread& t, hk_regs& r) {
        const uint64_t address = r.x[1], size = r.x[2];
        if (address % 0x1000 || size == 0 || size % 0x1000)
            return result::InvalidAddress;
        auto memory = std::make_shared<TransferMemory>();
        memory->memory = &t.process->memory;
        memory->address = address;
        memory->size = size;
        r.x[1] = t.process->Add(std::move(memory));
        return result::Success;
    }

    Result CreateEvent(hk_thread& t, hk_regs& r) {
        auto state = std::make_shared<EventState>();
        auto writable = std::make_shared<WritableEvent>();
        auto readable = std::make_shared<ReadableEvent>();
        readable->kernel = this;
        writable->state = readable->state = state;
        r.x[1] = t.process->Add(std::move(writable));
        r.x[2] = t.process->Add(std::move(readable));
        return result::Success;
    }

    Result SignalEvent(hk_thread& t, hk_regs& r) {
        auto event = t.process->Get<WritableEvent>(static_cast<uint32_t>(r.x[0]));
        if (!event)
            return result::InvalidHandle;
        SignalState(*event->state);
        return result::Success;
    }

    Result ClearEvent(hk_thread& t, hk_regs& r) {
        auto object = t.process->Find(static_cast<uint32_t>(r.x[0]));
        if (auto* writable = dynamic_cast<WritableEvent*>(object.get()))
            ClearState(*writable->state);
        else if (auto* readable = dynamic_cast<ReadableEvent*>(object.get()))
            ClearState(*readable->state);
        else
            return result::InvalidHandle;
        return result::Success;
    }

    Result ResetSignal(hk_thread& t, hk_regs& r) {
        auto event = t.process->Get<ReadableEvent>(static_cast<uint32_t>(r.x[0]));
        if (!event)
            return result::InvalidHandle;
        if (!event->state->signaled)
            return result::InvalidState;
        ClearState(*event->state);
        return result::Success;
    }

    Result GetThreadId(hk_thread& t, hk_regs& r) {
        const uint32_t handle = static_cast<uint32_t>(r.x[1]);
        std::shared_ptr<ThreadObject> object =
            handle == HK_CURRENT_THREAD ? t.object : t.process->Get<ThreadObject>(handle);
        if (!object)
            return result::InvalidHandle;
        r.x[1] = object->id;
        return result::Success;
    }

    static bool Load32(GuestMemory& memory, uint64_t address, uint32_t& value) {
        return memory.Read(address, std::as_writable_bytes(std::span(&value, 1)));
    }

    static bool Store32(GuestMemory& memory, uint64_t address, uint32_t value) {
        uint32_t expected = 0;
        if (!Load32(memory, address, expected))
            return false;
        for (;;) {
            const uint32_t seen = expected;
            if (!memory.CompareExchange32(address, expected, value))
                return false;
            if (expected == seen)
                return true;
        }
    }

    void Wake(hk_thread& t, Result result) {
        t.woken = true;
        t.wake_result = result;
        t.wait = hk_thread::Wait::None;
        t.lock_owner = nullptr;
        changed.notify_all();
    }

    // Releases the guest mutex at address held by owner: hands it to the
    // first thread waiting for it (marking the word if others still wait) or
    // clears it.
    Result ReleaseLock(hk_thread& owner, uint64_t address) {
        hk_thread* next = nullptr;
        bool more = false;
        for (hk_thread* w : lock_waiters) {
            if (w->lock_owner != &owner || w->mutex_address != address)
                continue;
            if (!next)
                next = w;
            else
                more = true;
        }
        uint32_t value = 0;
        if (next) {
            std::erase(lock_waiters, next);
            for (hk_thread* w : lock_waiters)
                if (w->lock_owner == &owner && w->mutex_address == address)
                    w->lock_owner = next;
            value = next->tag | (more ? kHasWaiters : 0);
        }
        if (!Store32(owner.process->memory, address, value))
            return result::InvalidCurrentMemory;
        if (next)
            Wake(*next, result::Success);
        return result::Success;
    }

    Result ArbitrateLock(Lock& lock, hk_thread& t, hk_regs& r) {
        const uint32_t owner_handle = static_cast<uint32_t>(r.x[0]);
        const uint64_t address = r.x[1];
        if (address % 4)
            return result::InvalidAddress;
        uint32_t value;
        if (!Load32(t.process->memory, address, value))
            return result::InvalidCurrentMemory;
        if (value != (owner_handle | kHasWaiters))
            return result::Success; // the owner changed; the guest retries
        hk_thread* owner = ThreadFromHandle(t, owner_handle);
        if (!owner)
            return result::InvalidHandle;
        t.wait = hk_thread::Wait::Mutex;
        t.mutex_address = address;
        t.tag = static_cast<uint32_t>(r.x[2]);
        t.lock_owner = owner;
        t.woken = false;
        lock_waiters.push_back(&t);
        changed.wait(lock, [&] { return t.woken; });
        return t.wake_result;
    }

    Result ArbitrateUnlock(hk_thread& t, hk_regs& r) {
        const uint64_t address = r.x[0];
        if (address % 4)
            return result::InvalidAddress;
        return ReleaseLock(t, address);
    }

    Result WaitProcessWideKeyAtomic(Lock& lock, hk_thread& t, hk_regs& r) {
        const uint64_t address = r.x[0];
        const uint64_t key = r.x[1];
        const auto timeout = static_cast<int64_t>(r.x[3]);
        if (address % 4)
            return result::InvalidAddress;
        if (const Result e = ReleaseLock(t, address))
            return e;
        t.wait = hk_thread::Wait::CondVar;
        t.mutex_address = address;
        t.cv_key = key;
        t.tag = static_cast<uint32_t>(r.x[2]);
        t.woken = false;
        cv_waiters.push_back(&t);
        if (!Store32(t.process->memory, key, 1)) {
            std::erase(cv_waiters, &t);
            t.wait = hk_thread::Wait::None;
            return result::InvalidCurrentMemory;
        }
        if (timeout >= 0) {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::nanoseconds(timeout);
            changed.wait_until(lock, deadline, [&] { return t.woken; });
        } else {
            changed.wait(lock, [&] { return t.woken; });
        }
        if (!t.woken) {
            std::erase(cv_waiters, &t);
            std::erase(lock_waiters, &t);
            t.wait = hk_thread::Wait::None;
            t.lock_owner = nullptr;
            return result::TimedOut;
        }
        return t.wake_result;
    }

    // Wakes up to count condition-variable waiters on key (all if count <= 0).
    // Each woken thread takes its mutex if it is free, or queues for it.
    Result SignalProcessWideKey(hk_thread& t, hk_regs& r) {
        const uint64_t key = r.x[0];
        const auto count = static_cast<int32_t>(r.x[1]);
        int32_t woken = 0;
        for (auto it = cv_waiters.begin(); it != cv_waiters.end() && (count <= 0 || woken < count);) {
            hk_thread* w = *it;
            if (w->cv_key != key || w->process != t.process) {
                ++it;
                continue;
            }
            it = cv_waiters.erase(it);
            ++woken;
            AcquireForWaiter(*w);
        }
        const bool remaining = std::any_of(cv_waiters.begin(), cv_waiters.end(),
                                           [&](hk_thread* w) { return w->cv_key == key && w->process == t.process; });
        if (!remaining)
            Store32(t.process->memory, key, 0);
        return result::Success;
    }

    void AcquireForWaiter(hk_thread& w) {
        GuestMemory& memory = w.process->memory;
        uint32_t value = 0;
        for (;;) {
            if (!Load32(memory, w.mutex_address, value))
                return Wake(w, result::InvalidCurrentMemory);
            uint32_t expected = value;
            const uint32_t desired = value == 0 ? w.tag : (value | kHasWaiters);
            if (!memory.CompareExchange32(w.mutex_address, expected, desired))
                return Wake(w, result::InvalidCurrentMemory);
            if (expected == value)
                break;
        }
        if (value == 0)
            return Wake(w, result::Success);
        hk_thread* owner = nullptr;
        if (auto object = w.process->Get<ThreadObject>(value & ~kHasWaiters))
            owner = object->thread;
        if (!owner)
            return Wake(w, result::InvalidHandle);
        w.wait = hk_thread::Wait::Mutex;
        w.lock_owner = owner;
        lock_waiters.push_back(&w);
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
    uint64_t next_thread_id = 0x50;
    std::vector<hk_thread*> lock_waiters; // waiting for a guest mutex
    std::deque<hk_thread*> cv_waiters;    // waiting on a condition variable key
    std::vector<std::unique_ptr<Link>> links;
    std::vector<std::unique_ptr<Request>> remote_requests;
    std::map<uint64_t, std::weak_ptr<EventState>> watches;
    uint64_t next_watch = 1;
};

namespace detail {

void ServerSession::LastHandleClosed() { state->kernel->CloseServer(*state); }
void ClientSession::LastHandleClosed() { state->kernel->CloseClient(*state); }
void ServerPort::LastHandleClosed() { kernel->ClosePort(*this); }
void ReadableEvent::LastHandleClosed() { kernel->CloseEvent(*this); }

} // namespace detail

Kernel::Kernel() : impl_(std::make_unique<Impl>()) {}

Kernel::~Kernel() { impl_->Shutdown(); }

std::shared_ptr<Process> Kernel::CreateProcess(uint64_t process_id, GuestMemory& memory) {
    return std::make_shared<Process>(process_id, memory);
}

hk_thread* Kernel::CreateThread(const std::shared_ptr<Process>& process, uint64_t tls_address) {
    std::lock_guard lock(impl_->mutex);
    auto thread = std::make_unique<hk_thread>();
    thread->kernel = impl_.get();
    thread->process = process;
    thread->tls = tls_address;
    thread->object = std::make_shared<ThreadObject>();
    thread->object->thread = thread.get();
    thread->object->id = impl_->next_thread_id++;
    return impl_->threads.emplace_back(std::move(thread)).get();
}

void Kernel::DestroyThread(hk_thread* thread) {
    std::lock_guard lock(impl_->mutex);
    thread->object->thread = nullptr;
    std::erase(impl_->lock_waiters, thread);
    std::erase(impl_->cv_waiters, thread);
    // Threads queued for a mutex this thread still owned can never get it.
    for (hk_thread* w : impl_->lock_waiters)
        if (w->lock_owner == thread)
            impl_->Wake(*w, result::InvalidHandle);
    std::erase_if(impl_->lock_waiters, [](hk_thread* w) { return w->woken; });
    std::erase_if(impl_->threads, [&](const auto& owned) { return owned.get() == thread; });
    impl_->changed.notify_all();
}

uint32_t Kernel::AddThreadHandle(hk_thread* thread) {
    std::lock_guard lock(impl_->mutex);
    return thread->process->Add(thread->object);
}

hk_thread* Kernel::FindThread(hk_thread* caller, uint32_t handle) {
    std::lock_guard lock(impl_->mutex);
    return impl_->ThreadFromHandle(*caller, handle);
}

uint64_t Kernel::ThreadId(hk_thread* thread) const { return thread->object->id; }

void Kernel::SetThreadUser(hk_thread* thread, void* user) { thread->user = user; }

void* Kernel::ThreadUser(hk_thread* thread) const { return thread->user; }

uint32_t Kernel::CreateSharedMemory(const std::shared_ptr<Process>& process, std::vector<std::byte> contents) {
    std::lock_guard lock(impl_->mutex);
    auto memory = std::make_shared<SharedMemory>();
    memory->contents = std::move(contents);
    return process->Add(std::move(memory));
}

bool Kernel::FindTransferMemory(const std::shared_ptr<Process>& process, uint32_t handle, TransferRange& out) const {
    std::lock_guard lock(impl_->mutex);
    auto memory = process->Get<TransferMemory>(handle);
    if (!memory)
        return false;
    out = {memory->memory, memory->address, memory->size};
    return true;
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

uint64_t Kernel::WatchEvent(const std::shared_ptr<Process>& process, uint32_t handle,
                            std::function<void(bool)> watch) {
    std::lock_guard lock(impl_->mutex);
    auto event = process->Get<ReadableEvent>(handle);
    if (!event)
        return 0;
    const uint64_t token = impl_->next_watch++;
    watch(event->state->signaled);
    event->state->watchers.emplace(token, std::move(watch));
    impl_->watches.emplace(token, event->state);
    return token;
}

void Kernel::Unwatch(uint64_t token) {
    std::lock_guard lock(impl_->mutex);
    auto it = impl_->watches.find(token);
    if (it == impl_->watches.end())
        return;
    if (auto state = it->second.lock())
        state->watchers.erase(token);
    impl_->watches.erase(it);
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
    case HK_SVC_SIGNAL_EVENT: result = kernel.SignalEvent(*thread, *regs); break;
    case HK_SVC_CLEAR_EVENT: result = kernel.ClearEvent(*thread, *regs); break;
    case HK_SVC_RESET_SIGNAL: result = kernel.ResetSignal(*thread, *regs); break;
    case HK_SVC_WAIT_SYNCHRONIZATION: result = kernel.WaitSynchronization(lock, *thread, *regs); break;
    case HK_SVC_CANCEL_SYNCHRONIZATION: result = kernel.CancelSynchronization(*thread, *regs); break;
    case HK_SVC_ARBITRATE_LOCK: result = kernel.ArbitrateLock(lock, *thread, *regs); break;
    case HK_SVC_ARBITRATE_UNLOCK: result = kernel.ArbitrateUnlock(*thread, *regs); break;
    case HK_SVC_WAIT_PROCESS_WIDE_KEY_ATOMIC: result = kernel.WaitProcessWideKeyAtomic(lock, *thread, *regs); break;
    case HK_SVC_SIGNAL_PROCESS_WIDE_KEY: result = kernel.SignalProcessWideKey(*thread, *regs); break;
    case HK_SVC_GET_THREAD_ID: result = kernel.GetThreadId(*thread, *regs); break;
    case HK_SVC_CREATE_EVENT: result = kernel.CreateEvent(*thread, *regs); break;
    case HK_SVC_CREATE_SHARED_MEMORY: result = kernel.CreateSharedMemory(*thread, *regs); break;
    case HK_SVC_MAP_SHARED_MEMORY: result = kernel.MapSharedMemory(*thread, *regs); break;
    case HK_SVC_UNMAP_SHARED_MEMORY: result = kernel.UnmapSharedMemory(*thread, *regs); break;
    case HK_SVC_CREATE_TRANSFER_MEMORY: result = kernel.CreateTransferMemory(*thread, *regs); break;
    default: result = hk::result::NotImplemented; break;
    }
    regs->x[0] = result;
}
