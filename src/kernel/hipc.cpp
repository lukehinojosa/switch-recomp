#include "hipc.h"

namespace hk::hipc {

Result Parse(std::span<const uint32_t, MessageWords> words, Layout& out) {
    const uint32_t header0 = words[0], header1 = words[1];
    const uint32_t send_statics = (header0 >> 16) & 0xf;
    const uint32_t send_buffers = (header0 >> 20) & 0xf;
    const uint32_t receive_buffers = (header0 >> 24) & 0xf;
    const uint32_t exchange_buffers = (header0 >> 28) & 0xf;
    const uint32_t receive_list = (header1 >> 10) & 0xf;
    if (send_statics || send_buffers || receive_buffers || exchange_buffers || receive_list)
        return result::NotImplemented;

    Layout layout;
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
    layout.data_word = word;
    layout.total_words = word + layout.data_count;
    if (layout.total_words > MessageWords)
        return result::MessageTooLarge;
    out = layout;
    return result::Success;
}

} // namespace hk::hipc
