#include "vi.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <span>
#include <thread>
#include <tuple>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);
const hk::Result kNotFound = MakeResult(114, 7); // vi

constexpr int64_t kWidth = 1920, kHeight = 1080;
constexpr uint64_t kDisplayId = 1;
constexpr int32_t kBinderId = 1; // every layer's buffer queue

// A binder parcel as vi carries it: a header naming where the data and the
// object list lie, then the data, written in 4-byte steps.
class ParcelReader {
public:
    explicit ParcelReader(const std::vector<std::byte>& bytes) {
        uint32_t header[4]{};
        if (bytes.size() >= sizeof header)
            std::memcpy(header, bytes.data(), sizeof header);
        if (header[1] <= bytes.size() && header[0] <= bytes.size() - header[1])
            data_.assign(bytes.begin() + header[1], bytes.begin() + header[1] + header[0]);
    }
    template <class T>
    T Read() {
        T value{};
        if (at_ + sizeof(T) <= data_.size())
            std::memcpy(&value, data_.data() + at_, sizeof(T));
        at_ += (sizeof(T) + 3) & ~size_t{3};
        return value;
    }
    void Skip(size_t bytes) { at_ += (bytes + 3) & ~size_t{3}; }
    // The interface token every transaction starts with: a strict-mode
    // policy and the interface's name in UTF-16.
    void SkipToken() {
        Read<int32_t>();
        const auto length = Read<int32_t>();
        if (length > 0)
            Skip((static_cast<size_t>(length) + 1) * 2);
    }
    // A flattened object: present, then its size and fd count, then its bytes.
    std::vector<std::byte> ReadObject() {
        if (!Read<uint32_t>())
            return {};
        const auto size = Read<uint32_t>();
        Read<uint32_t>(); // fds: none cross
        std::vector<std::byte> bytes;
        if (at_ + size <= data_.size())
            bytes.assign(data_.begin() + static_cast<ptrdiff_t>(at_), data_.begin() + static_cast<ptrdiff_t>(at_ + size));
        Skip(size);
        return bytes;
    }

private:
    std::vector<std::byte> data_;
    size_t at_ = 0;
};

class ParcelWriter {
public:
    template <class T>
    void Write(const T& value) {
        const auto* bytes = reinterpret_cast<const std::byte*>(&value);
        data_.insert(data_.end(), bytes, bytes + sizeof(T));
        data_.resize((data_.size() + 3) & ~size_t{3});
    }
    void WriteObject(std::span<const std::byte> object) {
        Write(uint32_t{1});
        Write(static_cast<uint32_t>(object.size()));
        Write(uint32_t{0});
        data_.insert(data_.end(), object.begin(), object.end());
        data_.resize((data_.size() + 3) & ~size_t{3});
    }
    // Lists a binder object about to be written at the current position;
    // the reader only accepts objects the parcel lists.
    void MarkObject() { objects_.push_back(static_cast<uint32_t>(data_.size())); }
    std::vector<std::byte> Serialize() const {
        std::vector<std::byte> out(0x10);
        const auto data_size = static_cast<uint32_t>(data_.size());
        const auto objects_size = static_cast<uint32_t>(4 * objects_.size());
        const uint32_t header[4] = {data_size, 0x10, objects_size, 0x10 + data_size};
        std::memcpy(out.data(), header, sizeof header);
        out.insert(out.end(), data_.begin(), data_.end());
        const auto* objects = reinterpret_cast<const std::byte*>(objects_.data());
        out.insert(out.end(), objects, objects + objects_size);
        return out;
    }

private:
    std::vector<std::byte> data_;
    std::vector<uint32_t> objects_;
};

// The parcel OpenLayer returns: a native window, a flattened binder object
// (0x28 bytes: type, flags, the binder's id, a cookie, the service's name).
std::vector<std::byte> NativeWindow() {
    ParcelWriter parcel;
    parcel.MarkObject();
    const uint32_t words[] = {2, 1, kBinderId, 0, 0, 0};
    for (uint32_t w : words)
        parcel.Write(w);
    parcel.Write(std::array<char, 8>{'d', 'i', 's', 'p', 'd', 'r', 'v', 0});
    parcel.Write(uint64_t{0});
    parcel.Write(uint32_t{0});
    return parcel.Serialize();
}

// A fence that has already passed: no syncpoints to wait on.
constexpr std::array<std::byte, 0x24> kNoFence{};

// The buffer queue behind every layer. Buffers are handed back as soon as
// they are queued, since nothing shows them.
struct BufferQueue {
    std::mutex mutex;
    std::map<int32_t, std::vector<std::byte>> buffers; // preallocated, by slot
    std::map<int32_t, bool> dequeued;
    int32_t next = 0;
    uint32_t release_writable = 0, release_readable = 0;
};

class BinderDriver final : public Interface {
public:
    BinderDriver(std::shared_ptr<BufferQueue> queue, bool trace) : queue_(std::move(queue)), trace_(trace) {}
    const char* Name() const override { return "vi IHOSBinderDriver"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0:   // TransactParcel(id, code, flags, A in) -> B out
        case 3: { // TransactParcelAuto
            const auto code = request.In<uint32_t>(4);
            ParcelReader in(request.InBuffer(0));
            ParcelWriter out;
            Transact(request, code, in, out);
            request.OutBuffer(out.Serialize());
            return 0;
        }
        case 1: // AdjustRefcount(id, add, type)
            return 0;
        case 2: { // GetNativeHandle(id, type) -> event: a buffer was released
            std::lock_guard lock(queue_->mutex);
            if (!queue_->release_readable) {
                std::tie(queue_->release_writable, queue_->release_readable) = request.create_event_pair();
                request.signal_event(queue_->release_writable);
            }
            response.copy.push_back(queue_->release_readable);
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    // IGraphicBufferProducer, by transaction code.
    void Transact(const Request& request, uint32_t code, ParcelReader& in, ParcelWriter& out) {
        in.SkipToken();
        std::lock_guard lock(queue_->mutex);
        auto& q = *queue_;
        const std::array<uint32_t, 4> queue_output{static_cast<uint32_t>(kWidth), static_cast<uint32_t>(kHeight), 0, 0};
        int32_t status = 0;
        switch (code) {
        case 1: { // RequestBuffer(slot) -> buffer
            auto it = q.buffers.find(in.Read<int32_t>());
            if (it == q.buffers.end())
                out.Write(uint32_t{0});
            else
                out.WriteObject(it->second);
            break;
        }
        case 3: { // DequeueBuffer(format, width, height, timestamps, usage) -> slot, fence
            int32_t slot = -1;
            for (size_t tried = 0; tried < q.buffers.size() && slot < 0; ++tried) {
                auto it = q.buffers.lower_bound(q.next);
                if (it == q.buffers.end())
                    it = q.buffers.begin();
                q.next = it->first + 1;
                if (!q.dequeued[it->first])
                    slot = it->first;
            }
            if (slot < 0 && q.buffers.empty())
                slot = 0;
            if (slot < 0) {
                status = -11; // WOULD_BLOCK
            } else {
                q.dequeued[slot] = true;
            }
            out.Write(slot);
            out.WriteObject(kNoFence);
            break;
        }
        case 7: { // QueueBuffer(slot, input) -> output
            const auto slot = in.Read<int32_t>();
            q.dequeued[slot] = false;
            if (q.release_writable)
                request.signal_event(q.release_writable);
            if (frames_++ == 0 || trace_)
                std::fprintf(stderr, "vi: frame %llu presented (slot %d)\n",
                             static_cast<unsigned long long>(frames_), slot);
            out.Write(queue_output);
            break;
        }
        case 8: // CancelBuffer(slot, fence)
            q.dequeued[in.Read<int32_t>()] = false;
            if (q.release_writable)
                request.signal_event(q.release_writable);
            break;
        case 9: { // Query(what) -> value
            const auto what = in.Read<int32_t>();
            const int32_t values[] = {static_cast<int32_t>(kWidth), static_cast<int32_t>(kHeight), 1, 2};
            if (what >= 0 && what < static_cast<int32_t>(std::size(values)))
                out.Write(values[what]);
            else
                out.Write(int32_t{0});
            break;
        }
        case 10: // Connect(listener, api, controlled by app) -> output
            out.Write(queue_output);
            break;
        case 14: { // SetPreallocatedBuffer(slot, buffer)
            const auto slot = in.Read<int32_t>();
            auto buffer = in.ReadObject();
            if (buffer.empty())
                q.buffers.erase(slot);
            else
                q.buffers[slot] = std::move(buffer);
            break;
        }
        case 2:  // SetBufferCount
        case 11: // Disconnect
        case 13: // AllocateBuffers
            break;
        default:
            std::fprintf(stderr, "vi: binder transaction %u not handled\n", code);
            status = -22; // BAD_VALUE
            break;
        }
        if (trace_)
            std::fprintf(stderr, "vi: binder transaction %u -> %d\n", code, status);
        out.Write(status);
    }

    std::shared_ptr<BufferQueue> queue_;
    bool trace_;
    uint64_t frames_ = 0;
};

// The display's vsync: an event signalled 60 times a second from a host
// thread, created on first request.
struct Vsync {
    std::mutex mutex;
    uint32_t readable = 0;

    uint32_t Get(const Request& request) {
        std::lock_guard lock(mutex);
        if (!readable) {
            uint32_t writable;
            std::tie(writable, readable) = request.create_event_pair();
            std::thread([signal = request.signal_event, writable] {
                auto next = std::chrono::steady_clock::now();
                for (;;) {
                    next += std::chrono::microseconds(16667);
                    std::this_thread::sleep_until(next);
                    signal(writable);
                }
            }).detach();
        }
        return readable;
    }
};

struct Display {
    std::shared_ptr<BufferQueue> queue = std::make_shared<BufferQueue>();
    Vsync vsync;
    uint64_t next_layer = 1;
    bool trace = false;
};

using Handler = std::function<hk::Result(const Request&, Response&)>;

class Commands final : public Interface {
public:
    Commands(std::string name, std::map<uint32_t, Handler> commands)
        : name_(std::move(name)), commands_(std::move(commands)) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request& request, Response& response) override {
        auto it = commands_.find(request.command);
        return it == commands_.end() ? kUnknown : it->second(request, response);
    }

private:
    std::string name_;
    std::map<uint32_t, Handler> commands_;
};

Handler Accept() {
    return [](const Request&, Response&) { return hk::Result{0}; };
}
template <class T>
Handler Value(T value) {
    return [value](const Request&, Response& response) {
        response.Out(value);
        return hk::Result{0};
    };
}

std::shared_ptr<Interface> SystemDisplayService() {
    return std::make_shared<Commands>("vi ISystemDisplayService", std::map<uint32_t, Handler>{
        {1200, Value<uint64_t>(0)},   // GetZOrderCountMin
        {1202, Value<uint64_t>(255)}, // GetZOrderCountMax
        {1203, Value(std::array<int32_t, 2>{static_cast<int32_t>(kWidth), static_cast<int32_t>(kHeight)})},
        {2201, Accept()},             // SetLayerPosition
        {2203, Accept()},             // SetLayerSize
        {2205, Accept()},             // SetLayerZ
        {2207, Accept()},             // SetLayerVisibility
        {3200, [](const Request&, Response& response) { // GetDisplayMode -> width, height, refresh rate, unknown
             response.Out(std::array<uint32_t, 2>{static_cast<uint32_t>(kWidth), static_cast<uint32_t>(kHeight)});
             response.Out(60.0f);
             response.Out(uint32_t{0});
             return hk::Result{0};
         }},
    });
}

std::shared_ptr<Interface> ManagerDisplayService(std::shared_ptr<Display> display) {
    return std::make_shared<Commands>("vi IManagerDisplayService", std::map<uint32_t, Handler>{
        {2010, [display](const Request&, Response& response) { // CreateManagedLayer -> layer id
             response.Out(display->next_layer++);
             return hk::Result{0};
         }},
        {2011, Accept()}, // DestroyManagedLayer
        {6000, Accept()}, // AddToLayerStack
        {6002, Accept()}, // SetLayerVisibility
        {7000, Accept()}, // SetContentVisibility
    });
}

std::shared_ptr<Interface> ApplicationDisplayService(std::shared_ptr<Display> display) {
    auto binder = [display](const Request&, Response& response) {
        response.objects.push_back(std::make_shared<BinderDriver>(display->queue, display->trace));
        return hk::Result{0};
    };
    auto layer_parcel = [](const Request& request, Response& response) {
        const auto parcel = NativeWindow();
        request.OutBuffer(parcel);
        response.Out(static_cast<uint64_t>(parcel.size()));
    };
    return std::make_shared<Commands>("vi IApplicationDisplayService", std::map<uint32_t, Handler>{
        {100, binder}, // GetRelayService
        {101, [](const Request&, Response& response) { // GetSystemDisplayService
             response.objects.push_back(SystemDisplayService());
             return hk::Result{0};
         }},
        {102, [display](const Request&, Response& response) { // GetManagerDisplayService
             response.objects.push_back(ManagerDisplayService(display));
             return hk::Result{0};
         }},
        {103, binder}, // GetIndirectDisplayTransactionService
        {1000, [](const Request& request, Response& response) { // ListDisplays -> count, B
             std::array<std::byte, 0x60> info{};
             std::memcpy(info.data(), "Default", 7);
             const uint64_t fields[] = {1, static_cast<uint64_t>(kWidth), static_cast<uint64_t>(kHeight)};
             info[0x40] = std::byte{1};
             std::memcpy(info.data() + 0x48, fields, sizeof fields);
             request.OutBuffer(info);
             response.Out(uint64_t{1});
             return hk::Result{0};
         }},
        {1010, [](const Request& request, Response& response) { // OpenDisplay(name) -> id
             const auto name = request.In<std::array<char, 0x40>>(0);
             if (std::strncmp(name.data(), "Default", name.size()) != 0)
                 return kNotFound;
             response.Out(kDisplayId);
             return hk::Result{0};
         }},
        {1011, Value(kDisplayId)}, // OpenDefaultDisplay
        {1020, Accept()},          // CloseDisplay
        {1101, Accept()},          // SetDisplayEnabled
        {1102, Value(std::array<int64_t, 2>{kWidth, kHeight})}, // GetDisplayResolution
        {2020, [layer_parcel](const Request& request, Response& response) { // OpenLayer -> size, B
             layer_parcel(request, response);
             return hk::Result{0};
         }},
        {2021, Accept()}, // CloseLayer
        {2030, [display, layer_parcel](const Request& request, Response& response) { // CreateStrayLayer -> id, size, B
             response.Out(display->next_layer++);
             layer_parcel(request, response);
             return hk::Result{0};
         }},
        {2031, Accept()},                 // DestroyStrayLayer
        {2101, Accept()},                 // SetLayerScalingMode
        {2102, Value<uint64_t>(2)},       // ConvertScalingMode: fit to the layer
        {5202, [display](const Request& request, Response& response) { // GetDisplayVsyncEvent
             response.copy.push_back(display->vsync.Get(request));
             return hk::Result{0};
         }},
    });
}

std::shared_ptr<Interface> RootService(std::shared_ptr<Display> display, const char* name,
                                       std::initializer_list<uint32_t> commands) {
    std::map<uint32_t, Handler> table;
    for (uint32_t command : commands) {
        table[command] = [display](const Request&, Response& response) { // GetDisplayService(policy)
            response.objects.push_back(ApplicationDisplayService(display));
            return hk::Result{0};
        };
    }
    return std::make_shared<Commands>(name, std::move(table));
}

} // namespace

void AddDisplay(NativeHost& host, bool trace) {
    auto display = std::make_shared<Display>();
    display->trace = trace;
    host.Add("vi:u", 8, [display] { return RootService(display, "vi:u", {0}); });
    host.Add("vi:s", 8, [display] { return RootService(display, "vi:s", {1, 3}); });
    host.Add("vi:m", 8, [display] { return RootService(display, "vi:m", {2, 3}); });
}

} // namespace services
