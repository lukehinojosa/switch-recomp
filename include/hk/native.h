// Helpers for native (authored) servers and clients: an owned flat guest
// address space, HIPC message building and parsing, and the register
// marshalling a recompiled SVC stub performs. Used by the runtime's native
// services and by the tests.
#pragma once

#include "hk/kernel.h"

#include <cstring>
#include <map>
#include <string_view>
#include <vector>

class FlatMemory final : public hk::GuestMemory {
public:
    // ipc_size bytes after the first size are kept for IPC buffer mappings.
    FlatMemory(uint64_t base, size_t size, size_t ipc_size = 0)
        : base_(base), ipc_base_(base + size), ipc_size_(ipc_size), bytes_(size + ipc_size) {}

    bool Read(uint64_t address, std::span<std::byte> out) override {
        if (!Contains(address, out.size()))
            return false;
        std::memcpy(out.data(), bytes_.data() + (address - base_), out.size());
        return true;
    }
    bool Write(uint64_t address, std::span<const std::byte> in) override {
        if (!Contains(address, in.size()))
            return false;
        std::memcpy(bytes_.data() + (address - base_), in.data(), in.size());
        return true;
    }

    bool CompareExchange32(uint64_t address, uint32_t& expected, uint32_t desired) override {
        if (!Contains(address, 4) || address % 4)
            return false;
        uint32_t current;
        std::memcpy(&current, bytes_.data() + (address - base_), 4);
        if (current != expected) {
            expected = current;
            return true;
        }
        std::memcpy(bytes_.data() + (address - base_), &desired, 4);
        return true;
    }

    bool MapIpcBuffer(uint64_t size, uint64_t& address) override {
        const uint64_t need = (size + 15) & ~uint64_t{15};
        uint64_t at = ipc_base_;
        for (const auto& [start, length] : ipc_mappings_) {
            if (start - at >= need)
                break;
            at = start + length;
        }
        if (at + need > ipc_base_ + ipc_size_)
            return false;
        ipc_mappings_[at] = need;
        std::memset(bytes_.data() + (at - base_), 0, need);
        address = at;
        return true;
    }
    void UnmapIpcBuffer(uint64_t address, uint64_t) override { ipc_mappings_.erase(address); }
    size_t IpcMappings() const { return ipc_mappings_.size(); }
    // Shared memory may go anywhere inside the first size bytes.
    bool MapAt(uint64_t address, uint64_t size) override { return Contains(address, size) && address < ipc_base_; }

    uint32_t Word(uint64_t address) {
        uint32_t value{};
        Read(address, std::as_writable_bytes(std::span(&value, 1)));
        return value;
    }
    void WriteWords(uint64_t address, std::span<const uint32_t> words) { Write(address, std::as_bytes(words)); }
    void WriteString(uint64_t address, std::string_view text) {
        std::vector<char> bytes(text.begin(), text.end());
        bytes.push_back('\0');
        Write(address, std::as_bytes(std::span(bytes)));
    }
    std::vector<std::byte> Snapshot(uint64_t address, size_t size) {
        std::vector<std::byte> out(size);
        Read(address, out);
        return out;
    }

private:
    bool Contains(uint64_t address, size_t size) const {
        return address >= base_ && size <= bytes_.size() && address - base_ <= bytes_.size() - size;
    }
    uint64_t base_;
    uint64_t ipc_base_;
    uint64_t ipc_size_;
    std::vector<std::byte> bytes_;
    std::map<uint64_t, uint64_t> ipc_mappings_; // start, length
};

struct StaticBuffer {
    uint64_t address = 0, size = 0;
    uint32_t index = 0;
};
struct MappedBuffer {
    uint64_t address = 0, size = 0;
};

struct Message {
    uint32_t type = 4;          // CMIF request; the kernel does not interpret it
    uint32_t extra_header0 = 0; // ORed into word 0, for malformed-message tests
    bool send_pid = false;
    uint64_t pid = 0;
    std::vector<uint32_t> copy, move, data;
    std::vector<StaticBuffer> statics;                     // X
    std::vector<MappedBuffer> sends, receives, exchanges; // A, B, W
    // Where this thread accepts X buffers when it next receives: one buffer
    // they are packed into (single) or one per X index.
    std::vector<MappedBuffer> receive_list;
    bool receive_list_single = true;
    uint32_t receive_list_word = 0; // 0: right after the data
};

inline void WriteMessage(FlatMemory& memory, uint64_t tls, const Message& message) {
    const bool special = message.send_pid || !message.copy.empty() || !message.move.empty();
    uint32_t receive_mode = 0;
    if (!message.receive_list.empty())
        receive_mode = message.receive_list_single ? 2 : static_cast<uint32_t>(message.receive_list.size()) + 2;
    std::vector<uint32_t> words{
        message.type | message.extra_header0 | static_cast<uint32_t>(message.statics.size()) << 16 |
            static_cast<uint32_t>(message.sends.size()) << 20 | static_cast<uint32_t>(message.receives.size()) << 24 |
            static_cast<uint32_t>(message.exchanges.size()) << 28,
        static_cast<uint32_t>(message.data.size()) | receive_mode << 10 | message.receive_list_word << 20 |
            (special ? 0x80000000u : 0)};
    if (special) {
        words.push_back((message.send_pid ? 1u : 0u) | static_cast<uint32_t>(message.copy.size()) << 1 |
                        static_cast<uint32_t>(message.move.size()) << 5);
        if (message.send_pid) {
            words.push_back(static_cast<uint32_t>(message.pid));
            words.push_back(static_cast<uint32_t>(message.pid >> 32));
        }
        words.insert(words.end(), message.copy.begin(), message.copy.end());
        words.insert(words.end(), message.move.begin(), message.move.end());
    }
    for (const auto& x : message.statics) {
        words.push_back((x.index & 0x3f) | static_cast<uint32_t>((x.address >> 36) & 7) << 6 |
                        static_cast<uint32_t>((x.address >> 32) & 0xf) << 12 | static_cast<uint32_t>(x.size) << 16);
        words.push_back(static_cast<uint32_t>(x.address));
    }
    for (const auto* list : {&message.sends, &message.receives, &message.exchanges}) {
        for (const auto& b : *list) {
            words.push_back(static_cast<uint32_t>(b.size));
            words.push_back(static_cast<uint32_t>(b.address));
            words.push_back(static_cast<uint32_t>((b.address >> 36) & 7) << 2 |
                            static_cast<uint32_t>((b.size >> 32) & 0xf) << 24 |
                            static_cast<uint32_t>((b.address >> 32) & 0xf) << 28);
        }
    }
    words.insert(words.end(), message.data.begin(), message.data.end());
    if (!message.receive_list.empty()) {
        if (message.receive_list_word)
            words.resize(message.receive_list_word);
        for (const auto& c : message.receive_list) {
            words.push_back(static_cast<uint32_t>(c.address));
            words.push_back(static_cast<uint32_t>((c.address >> 32) & 0xffff) | static_cast<uint32_t>(c.size) << 16);
        }
    }
    memory.WriteWords(tls, words);
}

inline Message ReadMessage(FlatMemory& memory, uint64_t tls) {
    Message message;
    const uint32_t header0 = memory.Word(tls), header1 = memory.Word(tls + 4);
    message.type = header0 & 0xffff;
    message.statics.resize((header0 >> 16) & 0xf);
    message.sends.resize((header0 >> 20) & 0xf);
    message.receives.resize((header0 >> 24) & 0xf);
    message.exchanges.resize((header0 >> 28) & 0xf);
    uint64_t at = tls + 8;
    auto next = [&] {
        const uint32_t value = memory.Word(at);
        at += 4;
        return value;
    };
    if (header1 >> 31) {
        const uint32_t special = next();
        message.send_pid = special & 1;
        if (message.send_pid) {
            message.pid = next();
            message.pid |= static_cast<uint64_t>(next()) << 32;
        }
        for (uint32_t i = 0; i < ((special >> 1) & 0xf); ++i)
            message.copy.push_back(next());
        for (uint32_t i = 0; i < ((special >> 5) & 0xf); ++i)
            message.move.push_back(next());
    }
    for (auto& x : message.statics) {
        const uint32_t w0 = next(), w1 = next();
        x.index = w0 & 0x3f;
        x.size = w0 >> 16;
        x.address = w1 | uint64_t{(w0 >> 12) & 0xf} << 32 | uint64_t{(w0 >> 6) & 7} << 36;
    }
    for (auto* list : {&message.sends, &message.receives, &message.exchanges}) {
        for (auto& b : *list) {
            const uint32_t w0 = next(), w1 = next(), w2 = next();
            b.size = w0 | uint64_t{(w2 >> 24) & 0xf} << 32;
            b.address = w1 | uint64_t{(w2 >> 28) & 0xf} << 32 | uint64_t{(w2 >> 2) & 7} << 36;
        }
    }
    for (uint32_t i = 0; i < (header1 & 0x3ff); ++i)
        message.data.push_back(next());
    return message;
}

namespace svc {

inline hk::Result Call(hk_thread* thread, uint32_t id, hk_regs& regs) {
    hk_svc(thread, id, &regs);
    return static_cast<hk::Result>(regs.x[0]);
}

inline hk::Result CloseHandle(hk_thread* t, uint32_t handle) {
    hk_regs r{};
    r.x[0] = handle;
    return Call(t, HK_SVC_CLOSE_HANDLE, r);
}

inline hk::Result ConnectToNamedPort(hk_thread* t, uint64_t name, uint32_t& out) {
    hk_regs r{};
    r.x[1] = name;
    const auto result = Call(t, HK_SVC_CONNECT_TO_NAMED_PORT, r);
    out = static_cast<uint32_t>(r.x[1]);
    return result;
}

inline hk::Result SendSyncRequest(hk_thread* t, uint32_t session) {
    hk_regs r{};
    r.x[0] = session;
    return Call(t, HK_SVC_SEND_SYNC_REQUEST, r);
}

inline hk::Result CreateSession(hk_thread* t, uint32_t& server, uint32_t& client) {
    hk_regs r{};
    const auto result = Call(t, HK_SVC_CREATE_SESSION, r);
    server = static_cast<uint32_t>(r.x[1]);
    client = static_cast<uint32_t>(r.x[2]);
    return result;
}

inline hk::Result AcceptSession(hk_thread* t, uint32_t port, uint32_t& out) {
    hk_regs r{};
    r.x[1] = port;
    const auto result = Call(t, HK_SVC_ACCEPT_SESSION, r);
    out = static_cast<uint32_t>(r.x[1]);
    return result;
}

inline hk::Result ReplyAndReceive(hk_thread* t, uint64_t handles, uint32_t count, uint32_t reply_target,
                                  int64_t timeout_ns, uint32_t& index) {
    hk_regs r{};
    r.x[1] = handles;
    r.x[2] = count;
    r.x[3] = reply_target;
    r.x[4] = static_cast<uint64_t>(timeout_ns);
    const auto result = Call(t, HK_SVC_REPLY_AND_RECEIVE, r);
    index = static_cast<uint32_t>(r.x[1]);
    return result;
}

inline hk::Result ManageNamedPort(hk_thread* t, uint64_t name, uint32_t max_sessions, uint32_t& out) {
    hk_regs r{};
    r.x[1] = name;
    r.x[2] = max_sessions;
    const auto result = Call(t, HK_SVC_MANAGE_NAMED_PORT, r);
    out = static_cast<uint32_t>(r.x[1]);
    return result;
}

inline hk::Result WaitSynchronization(hk_thread* t, uint64_t handles, uint32_t count, int64_t timeout_ns,
                                      uint32_t& index) {
    hk_regs r{};
    r.x[1] = handles;
    r.x[2] = count;
    r.x[3] = static_cast<uint64_t>(timeout_ns);
    const auto result = Call(t, HK_SVC_WAIT_SYNCHRONIZATION, r);
    index = static_cast<uint32_t>(r.x[1]);
    return result;
}

inline hk::Result CancelSynchronization(hk_thread* t, uint32_t thread_handle) {
    hk_regs r{};
    r.x[0] = thread_handle;
    return Call(t, HK_SVC_CANCEL_SYNCHRONIZATION, r);
}

inline hk::Result CreateEvent(hk_thread* t, uint32_t& writable, uint32_t& readable) {
    hk_regs r{};
    const auto result = Call(t, HK_SVC_CREATE_EVENT, r);
    writable = static_cast<uint32_t>(r.x[1]);
    readable = static_cast<uint32_t>(r.x[2]);
    return result;
}

inline hk::Result SignalEvent(hk_thread* t, uint32_t handle) {
    hk_regs r{};
    r.x[0] = handle;
    return Call(t, HK_SVC_SIGNAL_EVENT, r);
}

inline hk::Result ResetSignal(hk_thread* t, uint32_t handle) {
    hk_regs r{};
    r.x[0] = handle;
    return Call(t, HK_SVC_RESET_SIGNAL, r);
}

inline hk::Result ArbitrateLock(hk_thread* t, uint32_t owner, uint64_t address, uint32_t tag) {
    hk_regs r{};
    r.x[0] = owner;
    r.x[1] = address;
    r.x[2] = tag;
    return Call(t, HK_SVC_ARBITRATE_LOCK, r);
}

inline hk::Result ArbitrateUnlock(hk_thread* t, uint64_t address) {
    hk_regs r{};
    r.x[0] = address;
    return Call(t, HK_SVC_ARBITRATE_UNLOCK, r);
}

inline hk::Result WaitProcessWideKeyAtomic(hk_thread* t, uint64_t address, uint64_t key, uint32_t tag,
                                           int64_t timeout_ns) {
    hk_regs r{};
    r.x[0] = address;
    r.x[1] = key;
    r.x[2] = tag;
    r.x[3] = static_cast<uint64_t>(timeout_ns);
    return Call(t, HK_SVC_WAIT_PROCESS_WIDE_KEY_ATOMIC, r);
}

inline hk::Result SignalProcessWideKey(hk_thread* t, uint64_t key, int32_t count) {
    hk_regs r{};
    r.x[0] = key;
    r.x[1] = static_cast<uint32_t>(count);
    return Call(t, HK_SVC_SIGNAL_PROCESS_WIDE_KEY, r);
}

} // namespace svc
