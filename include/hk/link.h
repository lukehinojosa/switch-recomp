// A byte stream connecting two kernels in different host processes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace hk {

// Read and Write transfer exactly the requested bytes or report failure; a
// failure means the link is gone. Read and Write may run on different
// threads at the same time.
class ByteStream {
public:
    virtual ~ByteStream() = default;
    virtual bool Read(std::span<std::byte> out) = 0;
    virtual bool Write(std::span<const std::byte> in) = 0;
};

// Takes ownership of two handles: one to read from the peer, one to write to
// it. On Windows these are pipe HANDLE values; elsewhere file descriptors of
// pipes or sockets, two different ones.
std::unique_ptr<ByteStream> OpenPipeStream(uintptr_t read_handle, uintptr_t write_handle);

} // namespace hk
