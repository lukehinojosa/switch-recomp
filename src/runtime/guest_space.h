// One guest process's address space: a single host reservation covering the
// whole 39-bit guest range, committed region by region as the guest maps it.
#pragma once

#include "hk/kernel.h"

#include <cstdint>
#include <map>
#include <mutex>

namespace rt {

// Horizon memory permissions and the subset of memory states we track.
inline constexpr uint32_t kPermNone = 0, kPermR = 1, kPermW = 2, kPermX = 4, kPermRW = 3, kPermRX = 5;
inline constexpr uint32_t kStateFree = 0x00;
inline constexpr uint32_t kStateCode = 0x03;       // module .text and .rodata
inline constexpr uint32_t kStateCodeData = 0x04;   // module .data and .bss
inline constexpr uint32_t kStateNormal = 0x05;     // heap
inline constexpr uint32_t kStateShared = 0x06;
inline constexpr uint32_t kStateIpc = 0x0A;
inline constexpr uint32_t kStateStack = 0x0B;
inline constexpr uint32_t kStateThreadLocal = 0x0C;
inline constexpr uint32_t kStateInaccessible = 0x10;

struct Region {
    uint64_t address;
    uint64_t size;
    uint32_t state;
    uint32_t perm;
};

// Address-space layout reported through GetInfo. Values follow a 39-bit
// Horizon process; the module itself sits at its link base.
struct Layout {
    static constexpr uint64_t kAslrBase = 0x0008000000;
    static constexpr uint64_t kAslrSize = 0x7FF8000000;
    static constexpr uint64_t kHeapBase = 0x0100000000;
    static constexpr uint64_t kHeapSize = 0x0180000000;
    static constexpr uint64_t kAliasBase = 0x1000000000;
    static constexpr uint64_t kAliasSize = 0x1000000000;
    static constexpr uint64_t kStackBase = 0x2000000000;
    static constexpr uint64_t kStackSize = 0x0080000000;
};

class GuestSpace final : public hk::GuestMemory {
public:
    GuestSpace();
    ~GuestSpace() override;
    GuestSpace(const GuestSpace&) = delete;
    GuestSpace& operator=(const GuestSpace&) = delete;

    uint8_t* base() const { return base_; }

    // Commits [address, address+size) and records it. Fails if any page in
    // the range is already mapped. Page-aligned arguments only.
    bool Map(uint64_t address, uint64_t size, uint32_t state, uint32_t perm);
    // Releases [address, address+size), which must be wholly mapped; regions
    // at either edge are cut.
    bool Unmap(uint64_t address, uint64_t size);
    // The mapped region containing address, or the free gap around it.
    Region Query(uint64_t address) const;
    bool IsMapped(uint64_t address, uint64_t size) const;

    bool Read(uint64_t address, std::span<std::byte> out) override;
    bool Write(uint64_t address, std::span<const std::byte> in) override;
    bool CompareExchange32(uint64_t address, uint32_t& expected, uint32_t desired) override;
    // IPC buffers go in the alias region, where Horizon maps them too.
    bool MapIpcBuffer(uint64_t size, uint64_t& address) override;
    void UnmapIpcBuffer(uint64_t address, uint64_t size) override;
    bool MapAt(uint64_t address, uint64_t size) override;
    void UnmapAt(uint64_t address, uint64_t size) override;

private:
    uint8_t* base_{};
    mutable std::mutex mutex_;
    std::map<uint64_t, Region> regions_; // keyed by start address
};

} // namespace rt
