// Host-side kernel for running Horizon guest processes.
//
// Implements the IPC subset a sysmodule server needs: named ports, sessions,
// handle tables and HIPC message copy between processes with separate guest
// address spaces, within one host process or across a link to another (session
// ends and readable events cross it). Also
// the synchronization a guest runtime needs: thread and event objects,
// WaitSynchronization and the address arbiter behind guest mutexes and
// condition variables. Running threads is the caller's job.
#pragma once

#include "hk/svc.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace hk {

using Result = uint32_t;

constexpr Result MakeKernelResult(uint32_t description) { return 1u | (description << 9); }

namespace result {
inline constexpr Result Success = 0;
inline constexpr Result OutOfSessions = MakeKernelResult(7);
inline constexpr Result NotImplemented = MakeKernelResult(33);
inline constexpr Result InvalidAddress = MakeKernelResult(102);
inline constexpr Result InvalidCurrentMemory = MakeKernelResult(106);
inline constexpr Result InvalidHandle = MakeKernelResult(114);
inline constexpr Result InvalidPointer = MakeKernelResult(115);
inline constexpr Result TimedOut = MakeKernelResult(117);
inline constexpr Result Cancelled = MakeKernelResult(118);
inline constexpr Result OutOfRange = MakeKernelResult(119);
inline constexpr Result NotFound = MakeKernelResult(121);
inline constexpr Result SessionClosed = MakeKernelResult(123);
inline constexpr Result InvalidState = MakeKernelResult(125);
inline constexpr Result OutOfMemory = MakeKernelResult(104);
inline constexpr Result ReceiveListBroken = MakeKernelResult(258);
inline constexpr Result MessageTooLarge = MakeKernelResult(260);
} // namespace result

// One process's guest address space. Read and Write either transfer every
// byte or report failure without a partial transfer.
class GuestMemory {
public:
    virtual ~GuestMemory() = default;
    virtual bool Read(uint64_t address, std::span<std::byte> out) = 0;
    virtual bool Write(uint64_t address, std::span<const std::byte> in) = 0;
    // Atomic compare-and-swap of an aligned 32-bit word, for the address
    // arbiter. On a mismatch, expected receives the current value. Returns
    // false only if the word is not accessible.
    virtual bool CompareExchange32(uint64_t address, uint32_t& expected, uint32_t desired) {
        (void)address, (void)expected, (void)desired;
        return false;
    }
    // A zeroed read-write region for an A, B or W buffer received in a
    // request. The kernel copies the client's bytes in, copies B and W back
    // when the server replies, and then unmaps it. A memory that cannot map
    // makes such requests fail with OutOfMemory.
    virtual bool MapIpcBuffer(uint64_t size, uint64_t& address) {
        (void)size, (void)address;
        return false;
    }
    virtual void UnmapIpcBuffer(uint64_t address, uint64_t size) { (void)address, (void)size; }
    // A zeroed read-write region at a guest-chosen address, for shared memory.
    virtual bool MapAt(uint64_t address, uint64_t size) {
        (void)address, (void)size;
        return false;
    }
    virtual void UnmapAt(uint64_t address, uint64_t size) { (void)address, (void)size; }
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
    // Ends the thread for waiters (its handles become signalled), then frees
    // it. Handles to it stay valid until closed.
    void DestroyThread(hk_thread* thread);
    // Adds a handle to the thread in its own process's table.
    uint32_t AddThreadHandle(hk_thread* thread);
    // The thread a handle names in the caller's process, including the
    // current-thread pseudo-handle; null if there is none or it has exited.
    hk_thread* FindThread(hk_thread* caller, uint32_t handle);
    uint64_t ThreadId(hk_thread* thread) const;
    // An opaque pointer the runtime keeps per thread.
    void SetThreadUser(hk_thread* thread, void* user);
    void* ThreadUser(hk_thread* thread) const;

    // Shared memory created with the given contents, as a handle in process.
    // A process that maps it gets a copy of the contents at that moment:
    // later writes on either side are not seen by the other.
    uint32_t CreateSharedMemory(const std::shared_ptr<Process>& process, std::vector<std::byte> contents);
    // Where the transfer memory a handle names lies: in its creator's memory,
    // which the holder reads and writes in place. False if the handle names
    // none, or it came from another kernel.
    struct TransferRange {
        GuestMemory* memory{};
        uint64_t address{}, size{};
    };
    bool FindTransferMemory(const std::shared_ptr<Process>& process, uint32_t handle, TransferRange& out) const;
    // Closes every handle the process holds, waking peers as handles close.
    void DestroyProcess(const std::shared_ptr<Process>& process);

    // Connects this kernel to a kernel in another host process. Named ports
    // registered on either side become reachable from the other, and session
    // handles may cross in messages. Exactly one side passes initiator=true.
    // If the stream fails, every session across it closes.
    void AttachLink(std::unique_ptr<ByteStream> stream, bool initiator);

    // Calls watch with the signal state of a readable event the process
    // holds, now and after every change, for host code that mirrors it into
    // another kernel. watch runs with this kernel locked and must not call
    // into it. Returns a token for Unwatch, or 0 if the handle is not a
    // readable event. A readable event copied or moved across a link is a
    // mirror of the event in the other kernel and is watched the same way.
    uint64_t WatchEvent(const std::shared_ptr<Process>& process, uint32_t handle, std::function<void(bool)> watch);
    void Unwatch(uint64_t token);

    size_t HandleCount(const std::shared_ptr<Process>& process) const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace hk
