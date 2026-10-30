#include "nvdrv.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <span>
#include <string>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);

// The driver's own error codes, returned in the reply rather than as results.
enum NvResult : uint32_t {
    Success = 0,
    NotImplemented = 1,
    NotSupported = 2,
    NotInitialized = 3,
    BadParameter = 4,
    InsufficientMemory = 6,
    BadValue = 0xB,
};

// Fields of an ioctl's argument block.
template <class T>
T Get(const std::vector<std::byte>& bytes, size_t offset) {
    T value{};
    if (offset + sizeof(T) <= bytes.size())
        std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}
template <class T>
void Put(std::vector<std::byte>& bytes, size_t offset, T value) {
    if (offset + sizeof(T) <= bytes.size())
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

struct NvMap {
    uint32_t size{}, align{}, flags{}, heap{};
    uint8_t kind{};
    uint64_t address{}; // in the title's memory, once allocated
};

struct Mapping {
    uint32_t handle{};
    uint64_t offset{}, size{}; // within the handle's memory
};

// State every open device shares: a title's GPU, as the driver knows it.
struct Gpu {
    bool trace = false;
    hk::GuestMemory* memory{}; // the title's, from its transfer memory
    std::map<uint32_t, NvMap> handles;
    uint32_t next_handle = 1;
    std::map<uint64_t, Mapping> mappings; // by GPU address
    uint64_t next_address = 0x0200000000;  // where unfixed spaces and mappings go
    std::array<uint32_t, 192> syncpoints{};
    uint32_t next_syncpoint = 20;          // channels take ids from here
    uint64_t submissions = 0;

    // Translates a GPU address to the title's memory; 0 if unmapped.
    uint64_t GuestAddress(uint64_t gpu_address) const {
        auto it = mappings.upper_bound(gpu_address);
        if (it == mappings.begin())
            return 0;
        --it;
        const auto& m = it->second;
        auto handle = handles.find(m.handle);
        if (gpu_address >= it->first + m.size || handle == handles.end() || !handle->second.address)
            return 0;
        return handle->second.address + m.offset + (gpu_address - it->first);
    }

    uint64_t Reserve(uint64_t size, uint64_t align) {
        align = std::max<uint64_t>(align, 0x1000);
        next_address = (next_address + align - 1) & ~(align - 1);
        const uint64_t address = next_address;
        next_address += (size + 0xFFF) & ~uint64_t{0xFFF};
        return address;
    }
};

class Device {
public:
    explicit Device(std::shared_ptr<Gpu> gpu) : gpu_(std::move(gpu)) {}
    virtual ~Device() = default;
    virtual const char* Name() const = 0;
    // out holds the argument block (in, sized to the ioctl) to be returned;
    // in2 is the inline input of Ioctl2 and out2 the inline output of Ioctl3.
    virtual uint32_t Ioctl(uint32_t number, std::vector<std::byte>& out, const std::vector<std::byte>& in2,
                           std::vector<std::byte>& out2) = 0;

protected:
    std::shared_ptr<Gpu> gpu_;
};

// /dev/nvmap: handles naming blocks of the title's memory.
class NvMapDevice final : public Device {
public:
    using Device::Device;
    const char* Name() const override { return "nvmap"; }
    uint32_t Ioctl(uint32_t number, std::vector<std::byte>& a, const std::vector<std::byte>&,
                   std::vector<std::byte>&) override {
        auto& handles = gpu_->handles;
        switch (number) {
        case 0x0101: { // Create {size} -> {handle}
            const uint32_t handle = gpu_->next_handle++;
            handles[handle].size = Get<uint32_t>(a, 0);
            Put(a, 4, handle);
            return Success;
        }
        case 0x0103: // FromId {id} -> {handle}: ids are handles
            if (!handles.contains(Get<uint32_t>(a, 0)))
                return BadValue;
            Put(a, 4, Get<uint32_t>(a, 0));
            return Success;
        case 0x0104: { // Alloc {handle, heap mask, flags, align, kind, address}
            auto it = handles.find(Get<uint32_t>(a, 0));
            if (it == handles.end())
                return BadValue;
            it->second.heap = Get<uint32_t>(a, 4);
            it->second.flags = Get<uint32_t>(a, 8);
            it->second.align = Get<uint32_t>(a, 12);
            it->second.kind = Get<uint8_t>(a, 16);
            it->second.address = Get<uint64_t>(a, 24);
            return Success;
        }
        case 0x0105: { // Free {handle} -> {address, size, flags}
            auto it = handles.find(Get<uint32_t>(a, 0));
            if (it == handles.end())
                return BadValue;
            Put(a, 8, it->second.address);
            Put(a, 16, it->second.size);
            Put(a, 20, it->second.flags);
            handles.erase(it);
            return Success;
        }
        case 0x0109: { // Param {handle, param} -> {result}
            auto it = handles.find(Get<uint32_t>(a, 0));
            if (it == handles.end())
                return BadValue;
            const NvMap& h = it->second;
            const uint32_t param = Get<uint32_t>(a, 4);
            const uint32_t values[] = {0, h.size, h.align, 0, h.heap ? h.heap : 0x40000000u, h.kind, 0};
            Put(a, 8, param < std::size(values) ? values[param] : 0u);
            return param < std::size(values) ? Success : BadValue;
        }
        case 0x010E: // GetId {handle} -> {id}
            Put(a, 0, Get<uint32_t>(a, 4));
            return Success;
        default:
            return NotImplemented;
        }
    }
};

// /dev/nvhost-ctrl: syncpoints and the events that wait on them. Work
// completes as it is submitted, so every wait is already over.
class ControlDevice final : public Device {
public:
    using Device::Device;
    const char* Name() const override { return "nvhost-ctrl"; }
    uint32_t Ioctl(uint32_t number, std::vector<std::byte>& a, const std::vector<std::byte>&,
                   std::vector<std::byte>&) override {
        auto syncpoint = [&](uint32_t id) -> uint32_t& { return gpu_->syncpoints[id % gpu_->syncpoints.size()]; };
        switch (number) {
        case 0x0014: // SyncptRead {id} -> {value}
        case 0x001A: // SyncptReadMax
            Put(a, 4, syncpoint(Get<uint32_t>(a, 0)));
            return Success;
        case 0x0015: // SyncptIncr {id}
            ++syncpoint(Get<uint32_t>(a, 0));
            return Success;
        case 0x0016: // SyncptWait {id, threshold, timeout}
            return Success;
        case 0x0019: // SyncptWaitEx {id, threshold, timeout} -> {value}
            Put(a, 12, syncpoint(Get<uint32_t>(a, 0)));
            return Success;
        case 0x001B: // GetConfig {domain, name} -> {value}: no settings
            return NotSupported;
        case 0x001D: // EventWait {syncpoint, threshold, timeout, value}
        case 0x001E: // EventWaitAsync
            Put(a, 12, syncpoint(Get<uint32_t>(a, 0)));
            return Success;
        case 0x001C: // EventSignal
        case 0x001F: // EventRegister
        case 0x0020: // EventUnregister
        case 0x0021: // EventKill
            return Success;
        default:
            return NotImplemented;
        }
    }
};

// /dev/nvhost-ctrl-gpu: what the GPU is. The values are a Tegra X1's GM20B.
class GpuControlDevice final : public Device {
public:
    using Device::Device;
    const char* Name() const override { return "nvhost-ctrl-gpu"; }
    uint32_t Ioctl(uint32_t number, std::vector<std::byte>& a, const std::vector<std::byte>&,
                   std::vector<std::byte>& out2) override {
        switch (number) {
        case 0x4701: // ZcullGetCtxSize -> {size}
            Put(a, 0, uint32_t{1});
            return Success;
        case 0x4702: { // ZcullGetInfo
            const uint32_t info[] = {0x20, 0x20, 0x400, 0x800, 0x20, 0x20, 0xC0, 0x20, 0x40, 0x10};
            for (size_t i = 0; i < std::size(info); ++i)
                Put(a, 4 * i, info[i]);
            return Success;
        }
        case 0x4704: // ZbcSetTable
        case 0x4707: // FlushL2
            return Success;
        case 0x4705: { // GetCharacteristics {buffer size, buffer address} -> characteristics
            std::vector<std::byte> c(0xA0);
            const uint32_t head[] = {0x120, 0xB, 0xA1, 1};
            for (size_t i = 0; i < std::size(head); ++i)
                Put(c, 4 * i, head[i]);
            Put(c, 0x10, uint64_t{0x40000});   // L2 cache size
            Put(c, 0x18, uint64_t{0});         // on-board video memory
            const uint32_t middle[] = {2, 0x20, 0x20000, 0x20000, 0x1B, 0x30000, 1, 0x503, 0x503, 0x80, 0x28, 0};
            for (size_t i = 0; i < std::size(middle); ++i)
                Put(c, 0x20 + 4 * i, middle[i]);
            Put(c, 0x50, uint64_t{0x55});      // flags
            const uint32_t classes[] = {0x902D, 0xB197, 0xB1C0, 0xB06F, 0xA140, 0xB0B5,
                                        1, 0, 2, 1, 0, 1, 0x21D70, 0};
            for (size_t i = 0; i < std::size(classes); ++i)
                Put(c, 0x58 + 4 * i, classes[i]);
            std::memcpy(c.data() + 0x90, "gm20b", 5);
            Put(a, 0, uint64_t{0xA0});
            std::memcpy(a.data() + 0x10, c.data(), std::min<size_t>(c.size(), a.size() - 0x10));
            if (!out2.empty())
                std::memcpy(out2.data(), c.data(), std::min(c.size(), out2.size()));
            return Success;
        }
        case 0x4706: // GetTpcMasks {mask buffer size, ..} -> {mask}
            if (Get<uint32_t>(a, 0)) {
                Put(a, 0x10, uint32_t{3});
                if (out2.size() >= 4)
                    Put(out2, 0, uint32_t{3});
            }
            return Success;
        case 0x4714: // GetActiveSlotMask -> {slot, mask}
            Put(a, 0, uint32_t{7});
            Put(a, 4, uint32_t{1});
            return Success;
        case 0x471C: // GetGpuTime -> {nanoseconds}
            Put(a, 0, static_cast<uint64_t>(rt_counter_ns()));
            return Success;
        default:
            return NotImplemented;
        }
    }

private:
    static uint64_t rt_counter_ns() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                         std::chrono::steady_clock::now().time_since_epoch())
                                         .count());
    }
};

// /dev/nvhost-as-gpu: the GPU's address space.
class AddressSpaceDevice final : public Device {
public:
    using Device::Device;
    const char* Name() const override { return "nvhost-as-gpu"; }
    uint32_t Ioctl(uint32_t number, std::vector<std::byte>& a, const std::vector<std::byte>&,
                   std::vector<std::byte>& out2) override {
        Gpu& gpu = *gpu_;
        switch (number) {
        case 0x4101: // BindChannel {fd}
        case 0x4109: // AllocAsEx {big page size, ...}
        case 0x4114: // Remap {entries}
            return Success;
        case 0x4102: { // AllocSpace {pages, page size, flags, offset}
            const uint64_t size = uint64_t{Get<uint32_t>(a, 0)} * Get<uint32_t>(a, 4);
            if (!(Get<uint32_t>(a, 8) & 1)) // not at a fixed offset
                Put(a, 16, gpu.Reserve(size, std::max<uint64_t>(Get<uint32_t>(a, 4), 0x20000)));
            return Success;
        }
        case 0x4103: // FreeSpace {offset, pages, page size}
            return Success;
        case 0x4105: // UnmapBuffer {offset}
            gpu.mappings.erase(Get<uint64_t>(a, 0));
            return Success;
        case 0x4106: { // MapBufferEx {flags, kind, handle, page size, buffer offset, size, offset}
            const uint32_t flags = Get<uint32_t>(a, 0), handle = Get<uint32_t>(a, 8);
            auto it = gpu.handles.find(handle);
            if (it == gpu.handles.end())
                return BadValue;
            const uint64_t buffer_offset = Get<uint64_t>(a, 16);
            uint64_t size = Get<uint64_t>(a, 24);
            if (!size)
                size = it->second.size - buffer_offset;
            uint64_t offset = Get<uint64_t>(a, 32);
            if (flags & 0x100) { // remap within an existing mapping
                if (gpu.mappings.contains(offset))
                    gpu.mappings[offset] = {handle, buffer_offset, size};
                return Success;
            }
            if (!(flags & 1)) // not fixed: place it
                offset = gpu.Reserve(size, 0x20000);
            gpu.mappings[offset] = {handle, buffer_offset, size};
            Put(a, 32, offset);
            return Success;
        }
        case 0x4108: { // GetVaRegions {buffer address, buffer size} -> two regions
            std::vector<std::byte> regions(0x30);
            Put(regions, 0x00, uint64_t{0x04000000});
            Put(regions, 0x08, uint32_t{0x1000});
            Put(regions, 0x10, uint64_t{0x3BFFF});
            Put(regions, 0x18, uint64_t{0x0400000000});
            Put(regions, 0x20, uint32_t{0x20000});
            Put(regions, 0x28, uint64_t{0x1BFFF});
            Put(a, 8, uint32_t{0x30});
            std::memcpy(a.data() + 0x10, regions.data(), std::min<size_t>(0x30, a.size() - 0x10));
            if (!out2.empty())
                std::memcpy(out2.data(), regions.data(), std::min(regions.size(), out2.size()));
            return Success;
        }
        default:
            return NotImplemented;
        }
    }
};

// /dev/nvhost-gpu: a channel, through which the title submits command lists.
class ChannelDevice final : public Device {
public:
    using Device::Device;
    const char* Name() const override { return "nvhost-gpu"; }
    uint32_t Ioctl(uint32_t number, std::vector<std::byte>& a, const std::vector<std::byte>& in2,
                   std::vector<std::byte>&) override {
        Gpu& gpu = *gpu_;
        switch (number) {
        case 0x4801: // SetNvmapFd
        case 0x4803: // SetTimeout
        case 0x480B: // ZcullBind
        case 0x480C: // SetErrorNotifier
        case 0x480D: // SetPriority
        case 0x481D: // SetTimeslice
        case 0x4714: // SetUserData
            return Success;
        case 0x4809: // AllocObjCtx {class, flags} -> {object id}
            Put(a, 8, uint64_t{++objects_});
            return Success;
        case 0x481A: // AllocGpfifoEx2 {entries, flags, ...} -> {fence}
            syncpoint_ = gpu.next_syncpoint++;
            Put(a, 12, syncpoint_);
            Put(a, 16, gpu.syncpoints[syncpoint_]);
            return Success;
        case 0x4808:   // SubmitGpfifo {address, count, flags, fence} + entries -> {fence}
        case 0x481B: { // the same through Ioctl2, with the entries as its inline input
            const uint32_t count = Get<uint32_t>(a, 8), flags = Get<uint32_t>(a, 12);
            const std::vector<std::byte>& entries = in2.empty() ? a : in2;
            const size_t first = in2.empty() ? 0x18 : 0;
            Submit(entries, first, count);
            uint32_t& value = gpu.syncpoints[syncpoint_];
            if (flags & 2) // the submission increments the channel's syncpoint
                value += (flags & 0x100) ? 1 : 2; // one fewer without the wait-for-idle
            Put(a, 16, syncpoint_);
            Put(a, 20, value);
            return Success;
        }
        default:
            return NotImplemented;
        }
    }

private:
    // Records a submission; the first is shown in full, as the milestone it is.
    void Submit(const std::vector<std::byte>& entries, size_t first, uint32_t count) {
        Gpu& gpu = *gpu_;
        const bool show = gpu.submissions++ == 0 || gpu.trace;
        if (!show)
            return;
        std::fprintf(stderr, "nvdrv: GPU submission %" PRIu64 ": %u entries on syncpoint %u\n", gpu.submissions,
                     count, syncpoint_);
        for (uint32_t i = 0; i < count && i < 4; ++i) {
            const auto entry = Get<uint64_t>(entries, first + 8 * i);
            const uint64_t address = entry & 0xFFFFFFFFFCull;
            const uint32_t words = static_cast<uint32_t>(entry >> 42) & 0x1FFFFF;
            std::fprintf(stderr, "  entry %u: %u words at GPU %010" PRIx64, i, words, address);
            const uint64_t guest = gpu.GuestAddress(address);
            std::array<uint32_t, 8> head{};
            if (guest && gpu.memory &&
                gpu.memory->Read(guest, std::as_writable_bytes(std::span(head).first(std::min<size_t>(8, words))))) {
                std::fprintf(stderr, " (title %010" PRIx64 "):", guest);
                for (size_t w = 0; w < std::min<size_t>(8, words); ++w)
                    std::fprintf(stderr, " %08x", head[w]);
            }
            std::fprintf(stderr, "\n");
        }
    }

    uint32_t syncpoint_ = 0;
    uint64_t objects_ = 0;
};

// nvdrv: INvDrvServices.
class DriverService final : public Interface {
public:
    explicit DriverService(std::shared_ptr<Gpu> gpu) : gpu_(std::move(gpu)) {}
    const char* Name() const override { return "nvdrv"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // Open(path) -> fd, error
            const auto bytes = request.InBuffer(0);
            const std::string path(reinterpret_cast<const char*>(bytes.data()),
                                   strnlen(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
            std::unique_ptr<Device> device;
            if (path == "/dev/nvmap")
                device = std::make_unique<NvMapDevice>(gpu_);
            else if (path == "/dev/nvhost-ctrl")
                device = std::make_unique<ControlDevice>(gpu_);
            else if (path == "/dev/nvhost-ctrl-gpu")
                device = std::make_unique<GpuControlDevice>(gpu_);
            else if (path == "/dev/nvhost-as-gpu")
                device = std::make_unique<AddressSpaceDevice>(gpu_);
            else if (path == "/dev/nvhost-gpu")
                device = std::make_unique<ChannelDevice>(gpu_);
            if (gpu_->trace || !device)
                std::fprintf(stderr, "nvdrv: open %s%s\n", path.c_str(), device ? "" : " (no such device)");
            if (!device) {
                response.Out(std::array<uint32_t, 2>{0, NotSupported});
                return 0;
            }
            const uint32_t fd = next_fd_++;
            devices_[fd] = std::move(device);
            response.Out(std::array<uint32_t, 2>{fd, Success});
            return 0;
        }
        case 1:   // Ioctl(fd, number, in) -> out, error
        case 11:  // Ioctl2(fd, number, in, inline in) -> out, error
        case 12: { // Ioctl3(fd, number, in) -> out, inline out, error
            const uint32_t fd = request.In<uint32_t>(0), number = request.In<uint32_t>(4);
            auto it = devices_.find(fd);
            if (it == devices_.end()) {
                response.Out(BadParameter);
                return 0;
            }
            std::vector<std::byte> a = request.InBuffer(0);
            a.resize(std::max<size_t>(a.size(), (number >> 16) & 0x3FFF));
            const std::vector<std::byte> in2 = request.command == 11 ? request.InBuffer(1) : std::vector<std::byte>{};
            std::vector<std::byte> out2;
            if (request.command == 12 && request.receives.size() > 1)
                out2.resize(request.receives[1].size);
            const uint32_t error = it->second->Ioctl(number & 0xFFFF, a, in2, out2);
            if (error == NotImplemented || gpu_->trace)
                std::fprintf(stderr, "nvdrv: %s ioctl %08x -> %u\n", it->second->Name(), number, error);
            if (number & 0x80000000) // the ioctl returns its block
                request.OutBuffer(std::span(a).first(std::min<size_t>(a.size(), (number >> 16) & 0x3FFF)));
            if (!out2.empty())
                request.OutBuffer(out2, 1);
            response.Out(error);
            return 0;
        }
        case 2: // Close(fd) -> error
            response.Out(devices_.erase(request.In<uint32_t>(0)) ? Success : BadParameter);
            return 0;
        case 3: { // Initialize(transfer memory size, process, transfer memory) -> error
            hk::Kernel::TransferRange range;
            if (request.copy.size() >= 2 && request.transfer_memory(request.copy[1], range))
                gpu_->memory = range.memory;
            response.Out(Success);
            return 0;
        }
        case 4: // QueryEvent(fd, event id) -> event, error
            response.copy.push_back(request.create_event());
            response.Out(Success);
            return 0;
        case 8: // SetAruid(pid) -> error
            response.Out(Success);
            return 0;
        case 13: // SetGraphicsFirmwareMemoryMarginEnabled(bool)
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<Gpu> gpu_;
    std::map<uint32_t, std::unique_ptr<Device>> devices_;
    uint32_t next_fd_ = 1;
};

} // namespace

void AddNvdrv(NativeHost& host, bool trace) {
    auto gpu = std::make_shared<Gpu>();
    gpu->trace = trace;
    for (const char* name : {"nvdrv", "nvdrv:a", "nvdrv:s"})
        host.Add(name, 16, [gpu] { return std::make_shared<DriverService>(gpu); });
}

} // namespace services
