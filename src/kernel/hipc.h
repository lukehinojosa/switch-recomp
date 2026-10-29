// HIPC message layout in a thread's 0x100-byte message buffer.
#pragma once

#include "hk/kernel.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace hk::hipc {

inline constexpr size_t MessageWords = 0x100 / 4;

// Word positions of each part of a parsed message. In order: header, special
// header, PID, copied then moved handles, X (static) descriptors of 2 words,
// A, B and W buffer descriptors of 3 words, data words. The receive list (C
// descriptors of 2 words) is not part of the message sent; it says where this
// thread accepts X buffers when it next receives.
struct Layout {
    bool send_pid{};
    uint32_t copy_count{}, move_count{};
    uint32_t static_count{}, send_count{}, receive_count{}, exchange_count{};
    uint32_t pid_word{}, copy_word{}, move_word{}, static_word{}, buffer_word{}, data_word{}, data_count{};
    uint32_t total_words{}; // header through the last data word
    uint32_t receive_list_word{}, receive_list_count{};
    bool receive_list_single{}; // one C buffer that every X buffer is packed into

    uint32_t buffer_count() const { return send_count + receive_count + exchange_count; }
};

// Fails with NotImplemented for a receive list in the message buffer itself,
// and with MessageTooLarge when the declared parts do not fit the buffer.
Result Parse(std::span<const uint32_t, MessageWords> words, Layout& out);

// X: a pointer buffer the kernel copies into the receiver's receive list.
struct StaticDescriptor {
    uint32_t index{};
    uint64_t address{};
    uint64_t size{};
};
StaticDescriptor DecodeStatic(const uint32_t* words);
void EncodeStatic(const StaticDescriptor& d, uint32_t* words);

// A, B, W: buffers the kernel maps into the receiver for the request.
struct BufferDescriptor {
    uint64_t address{};
    uint64_t size{};
    uint32_t attributes{};
};
BufferDescriptor DecodeBuffer(const uint32_t* words);
void EncodeBuffer(const BufferDescriptor& d, uint32_t* words);

// C: one entry of a receive list.
struct ReceiveEntry {
    uint64_t address{};
    uint64_t size{};
};
ReceiveEntry DecodeReceive(const uint32_t* words);

} // namespace hk::hipc
