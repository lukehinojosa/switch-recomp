#include "module_link.h"

#include "hk/link.h"
#include "hk/native.h"
#include "kernel/platform.h"

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace client {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;
constexpr uint64_t kName = kBase + 0x200;
constexpr uint32_t kInMagic = 0x49434653, kOutMagic = 0x4F434653; // "SFCI", "SFCO"

} // namespace

struct ModuleLink::State {
    std::mutex lock;
    FlatMemory memory{kBase, 0x1000};
    hk::Kernel kernel;
    std::shared_ptr<hk::Process> process;
    hk_thread* thread = nullptr;
    std::unique_ptr<hk::platform::LinkedProcess> child; // destroyed first: killed

    ~State() {
        if (process)
            kernel.DestroyProcess(process);
    }
};

std::shared_ptr<ModuleLink> ModuleLink::Start(const ModuleOptions& options) {
    auto state = std::make_shared<State>();
    state->child = std::make_unique<hk::platform::LinkedProcess>(options.executable, options.arguments);
    auto stream = state->child->TakeStream();
    state->process = state->kernel.CreateProcess(options.process_id, state->memory);
    state->thread = state->kernel.CreateThread(state->process, kTls);
    state->kernel.AttachLink(std::move(stream), true);
    return std::shared_ptr<ModuleLink>(new ModuleLink(std::move(state)));
}

ModuleLink::ModuleLink(std::shared_ptr<State> state) : state_(std::move(state)) {}

ModuleLink::~ModuleLink() = default;

std::shared_ptr<Session> ModuleLink::Connect(std::string_view port, std::chrono::milliseconds wait) {
    const auto deadline = std::chrono::steady_clock::now() + wait;
    for (;;) {
        hk::Result result;
        uint32_t handle = 0;
        {
            std::lock_guard guard(state_->lock);
            state_->memory.WriteString(kName, port);
            result = svc::ConnectToNamedPort(state_->thread, kName, handle);
        }
        if (result == hk::result::Success)
            return std::make_shared<Session>(state_, handle);
        if (result != hk::result::NotFound || !Running() || std::chrono::steady_clock::now() >= deadline)
            return nullptr;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

bool ModuleLink::Running() const { return state_->child->Running(); }

Session::Session(std::shared_ptr<ModuleLink::State> link, uint32_t handle)
    : link_(std::move(link)), handle_(handle) {}

Session::~Session() {
    std::lock_guard guard(link_->lock);
    svc::CloseHandle(link_->thread, handle_);
}

Reply Session::Request(uint32_t command, std::span<const std::byte> raw, bool send_pid) {
    Message request;
    request.type = 4;
    request.send_pid = send_pid;
    // The CMIF header starts at the first 16-byte boundary after the HIPC
    // header; clients reserve 16 bytes for that alignment whatever part of it
    // is used, and servers check the data size against it.
    const uint32_t data_word = 2 + (send_pid ? 3 : 0);
    const uint32_t pad = (4 - data_word % 4) % 4;
    request.data.assign(pad, 0);
    request.data.insert(request.data.end(), {kInMagic, 0, command, 0});
    std::vector<uint32_t> words((raw.size() + 3) / 4);
    if (!raw.empty())
        std::memcpy(words.data(), raw.data(), raw.size());
    request.data.insert(request.data.end(), words.begin(), words.end());
    request.data.insert(request.data.end(), 4 - pad, 0);

    Reply reply;
    Message message;
    {
        std::lock_guard guard(link_->lock);
        WriteMessage(link_->memory, kTls, request);
        reply.kernel = svc::SendSyncRequest(link_->thread, handle_);
        if (reply.kernel)
            return reply;
        message = ReadMessage(link_->memory, kTls);
        for (uint32_t handle : message.copy) {
            if (auto event = Event::Adopt(link_, handle)) {
                reply.events.push_back(std::move(event));
            } else {
                svc::CloseHandle(link_->thread, handle);
                ++reply.copied_handles;
            }
        }
    }
    for (uint32_t handle : message.move) {
        if (auto event = Event::Adopt(link_, handle))
            reply.events.push_back(std::move(event));
        else
            reply.objects.push_back(std::make_shared<Session>(link_, handle));
    }
    const uint32_t reply_word = 2 + (message.move.empty() && message.copy.empty() ? 0 : 1) +
                                static_cast<uint32_t>(message.move.size() + message.copy.size());
    const size_t reply_pad = (4 - reply_word % 4) % 4;
    if (message.data.size() < reply_pad + 4 || message.data[reply_pad] != kOutMagic) {
        reply.malformed = true;
        return reply;
    }
    reply.result = message.data[reply_pad + 2];
    // The words after the output follow the 16 bytes of alignment space; a
    // reply's data size counts them, so drop the unused part at the end.
    const size_t first = reply_pad + 4;
    const size_t end = message.data.size() - std::min(message.data.size() - first, size_t{4} - reply_pad);
    for (size_t i = first; i < end; ++i) {
        const auto* bytes = reinterpret_cast<const std::byte*>(&message.data[i]);
        reply.raw.insert(reply.raw.end(), bytes, bytes + 4);
    }
    return reply;
}

struct EventMirror {
    std::mutex lock;
    std::condition_variable changed;
    bool signaled = false;
    std::function<void(bool)> on_change;
    uint64_t watch = 0;
};

std::shared_ptr<Event> Event::Adopt(const std::shared_ptr<ModuleLink::State>& link, uint32_t handle) {
    auto mirror = std::make_shared<EventMirror>();
    // The kernel keeps this callback, and with it the mirror, until Unwatch.
    mirror->watch = link->kernel.WatchEvent(link->process, handle, [mirror](bool signaled) {
        std::function<void(bool)> notify;
        {
            std::lock_guard guard(mirror->lock);
            mirror->signaled = signaled;
            notify = mirror->on_change;
        }
        mirror->changed.notify_all();
        if (notify)
            notify(signaled);
    });
    if (!mirror->watch)
        return nullptr;
    return std::make_shared<Event>(link, handle, std::move(mirror));
}

Event::Event(std::shared_ptr<ModuleLink::State> link, uint32_t handle, std::shared_ptr<EventMirror> mirror)
    : link_(std::move(link)), handle_(handle), mirror_(std::move(mirror)) {}

Event::~Event() {
    link_->kernel.Unwatch(mirror_->watch);
    std::lock_guard guard(link_->lock);
    svc::CloseHandle(link_->thread, handle_);
}

bool Event::Signaled() const {
    std::lock_guard guard(mirror_->lock);
    return mirror_->signaled;
}

bool Event::Wait(std::chrono::nanoseconds timeout) {
    std::unique_lock guard(mirror_->lock);
    const auto signaled = [&] { return mirror_->signaled; };
    if (timeout.count() < 0) {
        mirror_->changed.wait(guard, signaled);
        return true;
    }
    return mirror_->changed.wait_for(guard, timeout, signaled);
}

void Event::Clear() {
    std::lock_guard guard(link_->lock);
    svc::ClearEvent(link_->thread, handle_);
}

void Event::Watch(std::function<void(bool)> on_change) {
    std::lock_guard guard(mirror_->lock);
    mirror_->on_change = std::move(on_change);
}

} // namespace client
