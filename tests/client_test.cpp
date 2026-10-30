// The title-side client (src/client): starts cmif_host as a linked child and
// drives its "test" port through CMIF requests, sub-interfaces, the PID
// descriptor, a missing port and the child crashing.
#include "client/module_link.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

#define CHECK(condition)                                                                     \
    do {                                                                                     \
        if (!(condition)) {                                                                  \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                                      \
        }                                                                                    \
    } while (0)

constexpr uint64_t kPid = 0x1234567890;

std::filesystem::path HostPath() {
    wchar_t path[MAX_PATH];
    const DWORD size = GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::filesystem::path(std::wstring(path, size)).parent_path() / L"cmif_host.exe";
}

std::shared_ptr<client::ModuleLink> Start() {
    client::ModuleOptions options;
    options.executable = HostPath();
    options.process_id = kPid;
    return client::ModuleLink::Start(options);
}

void RequestsAndObjects() {
    auto link = Start();
    auto session = link->Connect("test", std::chrono::seconds(10));
    CHECK(session != nullptr);
    if (!session)
        return;

    // The server sees the input padded to words, then the request's unused
    // alignment space, and echoes all of it.
    const uint8_t input[] = {1, 2, 3, 4, 5, 6, 7};
    const auto echoed = session->Request(0, std::as_bytes(std::span(input)), false);
    CHECK(echoed.kernel == 0 && echoed.result == 0 && !echoed.malformed);
    CHECK(echoed.raw.size() == 16 && std::memcmp(echoed.raw.data(), input, sizeof input) == 0);

    const uint64_t placeholder = 0;
    const auto who = session->Request(2, std::as_bytes(std::span(&placeholder, 1)), true);
    uint64_t pid = 0;
    CHECK(who.result == 0 && who.raw.size() == 8);
    if (who.raw.size() == 8)
        std::memcpy(&pid, who.raw.data(), 8);
    CHECK(pid == kPid);

    const auto opened = session->Request(1, {}, false);
    CHECK(opened.result == 0 && opened.objects.size() == 1);
    if (opened.objects.size() == 1) {
        const auto again = opened.objects[0]->Request(0, std::as_bytes(std::span(input)), false);
        CHECK(again.result == 0 && again.raw.size() == 16);
    }
    CHECK(session->Request(7, {}, false).result != 0); // unknown command
    CHECK(link->Connect("absent", std::chrono::milliseconds(50)) == nullptr);
}

void ChildCrash() {
    auto link = Start();
    auto session = link->Connect("test", std::chrono::seconds(10));
    CHECK(session != nullptr);
    if (!session)
        return;
    const auto crashed = session->Request(3, {}, false);
    CHECK(crashed.kernel != 0);
    for (int i = 0; i < 500 && link->Running(); ++i)
        Sleep(10);
    CHECK(!link->Running());
    CHECK(session->Request(0, {}, false).kernel != 0);
    CHECK(link->Connect("test", std::chrono::milliseconds(50)) == nullptr);
}

} // namespace

int main() {
    RequestsAndObjects();
    ChildCrash();
    if (failures) {
        std::fprintf(stderr, "client_test: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("client_test: all passed\n");
    return 0;
}
