#include "guest_space.h"

#include "rt/ops.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>

namespace rt {

namespace {
constexpr uint64_t kSpaceSize = kAddressMask + 1;
constexpr uint64_t kPage = 0x1000;
} // namespace

GuestSpace::GuestSpace() {
    base_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, kSpaceSize, MEM_RESERVE, PAGE_NOACCESS));
    if (!base_) {
        std::fprintf(stderr, "could not reserve the guest address space\n");
        std::abort();
    }
}

GuestSpace::~GuestSpace() { VirtualFree(base_, 0, MEM_RELEASE); }

bool GuestSpace::Map(uint64_t address, uint64_t size, uint32_t state, uint32_t perm) {
    if (size == 0 || address % kPage || size % kPage || address + size > kSpaceSize)
        return false;
    std::lock_guard lock(mutex_);
    auto next = regions_.lower_bound(address);
    if (next != regions_.end() && next->first < address + size)
        return false;
    if (next != regions_.begin()) {
        auto prev = std::prev(next);
        if (prev->first + prev->second.size > address)
            return false;
    }
    // Host protection stays read-write: lifted code never executes guest
    // memory, and guest permission faults are not modelled yet.
    if (!VirtualAlloc(base_ + address, size, MEM_COMMIT, PAGE_READWRITE))
        return false;
    regions_.emplace(address, Region{address, size, state, perm});
    return true;
}

bool GuestSpace::Unmap(uint64_t address, uint64_t size) {
    std::lock_guard lock(mutex_);
    auto it = regions_.find(address);
    if (it == regions_.end() || it->second.size != size)
        return false;
    // Decommitting returns zeroed pages if the range is mapped again.
    VirtualFree(base_ + address, size, MEM_DECOMMIT);
    regions_.erase(it);
    return true;
}

Region GuestSpace::Query(uint64_t address) const {
    std::lock_guard lock(mutex_);
    auto next = regions_.upper_bound(address);
    uint64_t gap_start = 0;
    if (next != regions_.begin()) {
        const Region& r = std::prev(next)->second;
        if (address < r.address + r.size)
            return r;
        gap_start = r.address + r.size;
    }
    uint64_t gap_end = next == regions_.end() ? kSpaceSize : next->first;
    return Region{gap_start, gap_end - gap_start, kStateFree, kPermNone};
}

bool GuestSpace::IsMapped(uint64_t address, uint64_t size) const {
    if (size == 0)
        return true;
    uint64_t at = address;
    const uint64_t end = address + size;
    if (end < address || end > kSpaceSize)
        return false;
    while (at < end) {
        Region r = Query(at);
        if (r.state == kStateFree)
            return false;
        at = r.address + r.size;
    }
    return true;
}

bool GuestSpace::Read(uint64_t address, std::span<std::byte> out) {
    if (!IsMapped(address, out.size()))
        return false;
    std::memcpy(out.data(), base_ + address, out.size());
    return true;
}

bool GuestSpace::Write(uint64_t address, std::span<const std::byte> in) {
    if (!IsMapped(address, in.size()))
        return false;
    std::memcpy(base_ + address, in.data(), in.size());
    return true;
}

bool GuestSpace::MapIpcBuffer(uint64_t size, uint64_t& address) {
    const uint64_t length = (size + kPage - 1) & ~(kPage - 1);
    for (uint64_t at = Layout::kAliasBase; at + length <= Layout::kAliasBase + Layout::kAliasSize;) {
        const Region r = Query(at);
        if (r.state == kStateFree && r.address + r.size - at >= length) {
            if (!Map(at, length, kStateIpc, kPermRW))
                return false;
            address = at;
            return true;
        }
        at = r.address + r.size;
    }
    return false;
}

void GuestSpace::UnmapIpcBuffer(uint64_t address, uint64_t size) {
    Unmap(address, (size + kPage - 1) & ~(kPage - 1));
}

bool GuestSpace::MapAt(uint64_t address, uint64_t size) {
    return Map(address, (size + kPage - 1) & ~(kPage - 1), kStateShared, kPermRW);
}

void GuestSpace::UnmapAt(uint64_t address, uint64_t size) { Unmap(address, (size + kPage - 1) & ~(kPage - 1)); }

bool GuestSpace::CompareExchange32(uint64_t address, uint32_t& expected, uint32_t desired) {
    if (address % 4 || !IsMapped(address, 4))
        return false;
    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(base_ + address)).compare_exchange_strong(expected, desired);
    return true;
}

} // namespace rt
