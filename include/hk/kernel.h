// Host-side kernel for running Horizon guest processes.
//
// Implements the IPC subset a sysmodule server needs: named ports, sessions,
// handle tables and HIPC message copy between processes with separate guest
// address spaces, within one host process or across a link to another.
// Buffer descriptors are not supported yet; messages that carry them are
// rejected before delivery.
#pragma once

#include "hk/svc.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace hk {

using Result = uint32_t;

constexpr Result MakeKernelResult(uint32_t description) { return 1u | (description << 9); }

namespace result {
inline constexpr Result Success = 0;
inline constexpr Result OutOfSessions = MakeKernelResult(7);
inline constexpr Result NotImplemented = MakeKernelResult(33);
inline constexpr Result InvalidHandle = MakeKernelResult(114);
inline constexpr Result InvalidPointer = MakeKernelResult(115);
inline constexpr Result TimedOut = MakeKernelResult(117);
inline constexpr Result OutOfRange = MakeKernelResult(119);
inline constexpr Result NotFound = MakeKernelResult(121);
inline constexpr Result SessionClosed = MakeKernelResult(123);
inline constexpr Result InvalidState = MakeKernelResult(125);
inline constexpr Result MessageTooLarge = MakeKernelResult(260);
} // namespace result

// One process's guest address space. Read and Write either transfer every
// byte or report failure without a partial transfer.
class GuestMemory {
public:
    virtual ~GuestMemory() = default;
    virtual bool Read(uint64_t address, std::span<std::byte> out) = 0;
    virtual bool Write(uint64_t address, std::span<const std::byte> in) = 0;
};

class Process;
class ByteStream;

class Kernel {
public:
    Kernel();
    ~Kernel();
    Kernel(const Kernel&) = delete;
    Kernel& operator=(const Kernel&) = delete;

    std::shared_ptr<Process> CreateProcess(uint64_t process_id, GuestMemory& memory);
    // The thread's IPC message buffer is the first 0x100 bytes at tls_address.
    hk_thread* CreateThread(const std::shared_ptr<Process>& process, uint64_t tls_address);
    void DestroyThread(hk_thread* thread);
    // Closes every handle the process holds, waking peers as handles close.
    void DestroyProcess(const std::shared_ptr<Process>& process);

    // Connects this kernel to a kernel in another host process. Named ports
    // registered on either side become reachable from the other, and session
    // handles may cross in messages. Exactly one side passes initiator=true.
    // If the stream fails, every session across it closes.
    void AttachLink(std::unique_ptr<ByteStream> stream, bool initiator);

    size_t HandleCount(const std::shared_ptr<Process>& process) const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace hk
