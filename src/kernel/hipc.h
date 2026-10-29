// HIPC message layout in a thread's 0x100-byte message buffer.
#pragma once

#include "hk/kernel.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace hk::hipc {

inline constexpr size_t MessageWords = 0x100 / 4;

// Word positions of each part of a parsed message.
struct Layout {
    bool send_pid{};
    uint32_t copy_count{}, move_count{};
    uint32_t pid_word{}, copy_word{}, move_word{}, data_word{}, data_count{};
    uint32_t total_words{};
};

// Fails with NotImplemented for buffer descriptors or receive lists, and with
// MessageTooLarge when the declared parts do not fit the buffer.
Result Parse(std::span<const uint32_t, MessageWords> words, Layout& out);

} // namespace hk::hipc
