// Test-side guest helpers: an owned guest address space, HIPC message
// building and the register marshalling a recompiled SVC stub performs.
#pragma once

#include "hk/kernel.h"

#include <cstring>
#include <string_view>
#include <vector>

class TestMemory final : public hk::GuestMemory {
public:
    TestMemory(uint64_t base, size_t size) : base_(base), bytes_(size) {}

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
    std::vector<std::byte> bytes_;
};

struct Message {
    uint32_t type = 4;          // CMIF request; the kernel does not interpret it
    uint32_t extra_header0 = 0; // ORed into word 0, for malformed-message tests
    bool send_pid = false;
    uint64_t pid = 0;
    std::vector<uint32_t> copy, move, data;
};

inline void WriteMessage(TestMemory& memory, uint64_t tls, const Message& message) {
    const bool special = message.send_pid || !message.copy.empty() || !message.move.empty();
    std::vector<uint32_t> words{message.type | message.extra_header0,
                                static_cast<uint32_t>(message.data.size()) | (special ? 0x80000000u : 0)};
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
    words.insert(words.end(), message.data.begin(), message.data.end());
    memory.WriteWords(tls, words);
}

inline Message ReadMessage(TestMemory& memory, uint64_t tls) {
    Message message;
    const uint32_t header0 = memory.Word(tls), header1 = memory.Word(tls + 4);
    message.type = header0 & 0xffff;
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

} // namespace svc
