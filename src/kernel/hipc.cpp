#include "hipc.h"

namespace hk::hipc {

Result Parse(std::span<const uint32_t, MessageWords> words, Layout& out) {
    const uint32_t header0 = words[0], header1 = words[1];
    Layout layout;
    layout.static_count = (header0 >> 16) & 0xf;
    layout.send_count = (header0 >> 20) & 0xf;
    layout.receive_count = (header0 >> 24) & 0xf;
    layout.exchange_count = (header0 >> 28) & 0xf;
    const uint32_t receive_mode = (header1 >> 10) & 0xf;
    const uint32_t receive_offset = (header1 >> 20) & 0x7ff;
    if (receive_mode == 1)
        return result::NotImplemented; // receive into the message buffer itself

    layout.data_count = header1 & 0x3ff;
    uint32_t word = 2;
    if (header1 >> 31) {
        const uint32_t special = words[2];
        layout.send_pid = special & 1;
        layout.copy_count = (special >> 1) & 0xf;
        layout.move_count = (special >> 5) & 0xf;
        word = 3;
        if (layout.send_pid) {
            layout.pid_word = word;
            word += 2;
        }
    }
    layout.copy_word = word;
    word += layout.copy_count;
    layout.move_word = word;
    word += layout.move_count;
    layout.static_word = word;
    word += 2 * layout.static_count;
    layout.buffer_word = word;
    word += 3 * layout.buffer_count();
    layout.data_word = word;
    layout.total_words = word + layout.data_count;
    if (layout.total_words > MessageWords)
        return result::MessageTooLarge;

    if (receive_mode >= 2) {
        layout.receive_list_single = receive_mode == 2;
        layout.receive_list_count = receive_mode == 2 ? 1 : receive_mode - 2;
        layout.receive_list_word = receive_offset ? receive_offset : layout.total_words;
        if (layout.receive_list_word + 2 * layout.receive_list_count > MessageWords)
            return result::MessageTooLarge;
    }
    out = layout;
    return result::Success;
}

StaticDescriptor DecodeStatic(const uint32_t* w) {
    StaticDescriptor d;
    d.index = w[0] & 0x3f;
    d.size = w[0] >> 16;
    d.address = w[1] | static_cast<uint64_t>((w[0] >> 12) & 0xf) << 32 | static_cast<uint64_t>((w[0] >> 6) & 0x7) << 36;
    return d;
}

void EncodeStatic(const StaticDescriptor& d, uint32_t* w) {
    w[0] = (d.index & 0x3f) | static_cast<uint32_t>((d.address >> 36) & 0x7) << 6 |
           static_cast<uint32_t>((d.address >> 32) & 0xf) << 12 | static_cast<uint32_t>(d.size & 0xffff) << 16;
    w[1] = static_cast<uint32_t>(d.address);
}

BufferDescriptor DecodeBuffer(const uint32_t* w) {
    BufferDescriptor d;
    d.size = w[0] | static_cast<uint64_t>((w[2] >> 24) & 0xf) << 32;
    d.address = w[1] | static_cast<uint64_t>((w[2] >> 28) & 0xf) << 32 | static_cast<uint64_t>((w[2] >> 2) & 0x7) << 36;
    d.attributes = w[2] & 3;
    return d;
}

void EncodeBuffer(const BufferDescriptor& d, uint32_t* w) {
    w[0] = static_cast<uint32_t>(d.size);
    w[1] = static_cast<uint32_t>(d.address);
    w[2] = (d.attributes & 3) | static_cast<uint32_t>((d.address >> 36) & 0x7) << 2 |
           static_cast<uint32_t>((d.size >> 32) & 0xf) << 24 | static_cast<uint32_t>((d.address >> 32) & 0xf) << 28;
}

ReceiveEntry DecodeReceive(const uint32_t* w) {
    ReceiveEntry e;
    e.address = w[0] | static_cast<uint64_t>(w[1] & 0xffff) << 32;
    e.size = w[1] >> 16;
    return e;
}

} // namespace hk::hipc
