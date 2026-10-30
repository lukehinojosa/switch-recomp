// The C interface of the module client (include/hk/module_client.h).
#include "hk/module_client.h"

#include "client/module_link.h"

#include <cstdio>
#include <cstring>
#include <exception>

struct hk_module {
    std::shared_ptr<client::ModuleLink> link;
};

struct hk_module_session {
    std::shared_ptr<client::Session> session;
};

struct hk_module_event {
    std::shared_ptr<client::Event> event;
};

extern "C" {

hk_module* hk_module_start(const char* executable, const char* const* arguments, size_t argument_count,
                           uint64_t process_id, char* error, size_t error_size) {
    try {
        client::ModuleOptions options;
        options.executable = std::filesystem::path(reinterpret_cast<const char8_t*>(executable));
        for (size_t i = 0; i < argument_count; ++i) options.arguments.emplace_back(arguments[i]);
        options.process_id = process_id;
        return new hk_module{client::ModuleLink::Start(options)};
    } catch (const std::exception& e) {
        if (error && error_size) std::snprintf(error, error_size, "%s", e.what());
        return nullptr;
    }
}

void hk_module_stop(hk_module* module) {
    delete module;
}

int hk_module_running(const hk_module* module) {
    return module && module->link->Running();
}

hk_module_session* hk_module_connect(hk_module* module, const char* port, uint32_t wait_ms) {
    try {
        auto session = module->link->Connect(port, std::chrono::milliseconds(wait_ms));
        return session ? new hk_module_session{std::move(session)} : nullptr;
    } catch (const std::exception&) {
        return nullptr;
    }
}

int hk_module_request(hk_module_session* session, uint32_t command, const void* raw, size_t raw_size,
                      int send_pid, hk_module_reply* reply) {
    *reply = {};
    try {
        auto r = session->session->Request(
            command, {static_cast<const std::byte*>(raw), raw_size}, send_pid != 0);
        reply->kernel = r.kernel;
        reply->result = r.result;
        reply->copied_handles = r.copied_handles;
        reply->malformed = r.malformed;
        if (!r.raw.empty()) {
            auto* bytes = new uint8_t[r.raw.size()];
            std::memcpy(bytes, r.raw.data(), r.raw.size());
            reply->raw = bytes;
            reply->raw_size = r.raw.size();
        }
        if (!r.objects.empty()) {
            reply->objects = new hk_module_session*[r.objects.size()];
            for (size_t i = 0; i < r.objects.size(); ++i)
                reply->objects[i] = new hk_module_session{std::move(r.objects[i])};
            reply->object_count = r.objects.size();
        }
        if (!r.events.empty()) {
            reply->events = new hk_module_event*[r.events.size()];
            for (size_t i = 0; i < r.events.size(); ++i)
                reply->events[i] = new hk_module_event{std::move(r.events[i])};
            reply->event_count = r.events.size();
        }
        return 0;
    } catch (const std::exception&) {
        hk_module_reply_free(reply);
        return 1;
    }
}

void hk_module_reply_free(hk_module_reply* reply) {
    delete[] reply->raw;
    delete[] reply->objects;
    delete[] reply->events;
    reply->raw = nullptr;
    reply->objects = nullptr;
    reply->events = nullptr;
    reply->raw_size = reply->object_count = reply->event_count = 0;
}

void hk_module_close(hk_module_session* session) {
    delete session;
}

int hk_module_event_signaled(hk_module_event* event) {
    return event->event->Signaled();
}

int hk_module_event_wait(hk_module_event* event, int64_t timeout_ns) {
    return event->event->Wait(std::chrono::nanoseconds(timeout_ns));
}

void hk_module_event_clear(hk_module_event* event) {
    event->event->Clear();
}

void hk_module_event_watch(hk_module_event* event, void (*on_change)(void*, int), void* user) {
    if (!on_change) {
        event->event->Watch(nullptr);
        return;
    }
    event->event->Watch([on_change, user](bool signaled) { on_change(user, signaled); });
}

void hk_module_event_close(hk_module_event* event) {
    delete event;
}

} // extern "C"
