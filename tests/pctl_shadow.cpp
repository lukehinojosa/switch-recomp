// Shadow check of the recompiled pctl against the verified service in
// mk8-recomp, without the game: starts module_host as a linked child with
// MK8D registered as the application, sends the requests MK8D makes and
// compares each reply with what the verified service answers.
//
//   pctl_shadow <module_host.exe> <pctl.load.elf> <control.nacp> [boot mode]
//
// The expected replies are transcribed from mk8-recomp's
// verified_services/services/parental_control.cpp: port "pctl" has
// capabilities 0x303; pctl:s, pctl:a and pctl:r are opened with none there,
// although firmware gives them their own (MK8D never calls methods on them).
// A comparison passes when the results match and, on success, the verified
// output bytes, moved-object count and copied events (with their signal
// state) match. The verified service creates 1432's event unsignalled and
// never signals it. Exit code: the number of
// differences, or 100 if the module could not be reached.
#include "client/module_link.h"

#ifdef _WIN32
#include <process.h>
#include <stdlib.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

namespace {

constexpr uint64_t kMk8dProgram = 0x0100152000022000;
constexpr uint32_t kNoCapability = 0x1068e;

struct Expected {
    uint32_t result = 0;
    std::vector<uint8_t> output; // compared on success
    size_t objects = 0;
    size_t events = 0; // copied, unsignalled
};

int differences = 0;

void Compare(const char* label, const client::Reply& reply, const Expected& expected) {
    if (reply.kernel || reply.malformed) {
        std::printf("FAIL %-44s no reply (kernel %08x%s)\n", label, reply.kernel, reply.malformed ? ", malformed" : "");
        ++differences;
        return;
    }
    std::string output;
    for (size_t i = 0; i < reply.raw.size() && i < 8; ++i) {
        char hex[4];
        std::snprintf(hex, sizeof hex, "%02x", static_cast<unsigned>(reply.raw[i]));
        output += hex;
    }
    bool same = reply.result == expected.result;
    if (same && expected.result == 0) {
        same = reply.objects.size() == expected.objects && reply.raw.size() >= expected.output.size() &&
               std::memcmp(reply.raw.data(), expected.output.data(), expected.output.size()) == 0 &&
               reply.events.size() == expected.events;
        for (const auto& event : reply.events)
            same = same && !event->Signaled();
    }
    std::string events; // S: signalled
    for (const auto& event : reply.events)
        events += event->Signaled() ? "S" : "-";
    std::printf("%s %-44s result %08x (verified %08x), objects %zu (%zu), events %s (%zu), output %s\n",
                same ? "same" : "DIFF", label, reply.result, expected.result, reply.objects.size(), expected.objects,
                events.empty() ? "none" : events.c_str(), expected.events, output.empty() ? "-" : output.c_str());
    if (!same)
        ++differences;
}

const std::byte kCreateInput[8] = {}; // reserved u64, then the PID descriptor

// The child service calls MK8D makes, each without input.
void ChildCalls(const std::string& prefix, client::Session& child) {
    Compare((prefix + " 1031 IsRestrictionEnabled").c_str(), child.Request(1031, {}, false), {0, {0}, 0});
    Compare((prefix + " 1062 GetStereoVisionRestriction").c_str(), child.Request(1062, {}, false), {0, {0}, 0});
    Compare((prefix + " 1065 IsStereoVisionPermitted").c_str(), child.Request(1065, {}, false), {0, {1}, 0});
    Compare((prefix + " 1432 GetSynchronizationEvent").c_str(), child.Request(1432, {}, false), {0, {}, 0, 1});
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: pctl_shadow <module_host.exe> <pctl.load.elf> <control.nacp> [boot mode]\n");
        return 2;
    }
    const uint64_t pid = static_cast<uint64_t>(getpid());
    client::ModuleOptions options;
    options.executable = argv[1];
    options.process_id = pid;
    char version[16];
    std::snprintf(version, sizeof version, "%u", 0x170000u); // 4.0.1, the dump's update
    char program[24];
    std::snprintf(program, sizeof program, "%016llx", static_cast<unsigned long long>(kMk8dProgram));
    options.arguments = {"--application", std::to_string(pid), program, version, argv[3], argv[2]};
    if (argc > 4)
#ifdef _WIN32
        _putenv_s("RT_BOOT_MODE", argv[4]); // inherited by the module host
#else
        setenv("RT_BOOT_MODE", argv[4], 1);
#endif
    std::shared_ptr<client::ModuleLink> link;
    try {
        link = client::ModuleLink::Start(options);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "pctl_shadow: %s\n", error.what());
        return 100;
    }

    auto pctl = link->Connect("pctl", std::chrono::seconds(30));
    if (!pctl) {
        std::fprintf(stderr, "pctl_shadow: the module did not register pctl\n");
        return 100;
    }
    // Registration comes before the module's server loop is ready; a request
    // queued now simply waits for it.

    // CreateServiceWithoutInitialize, then Initialize: the sequence the
    // verified bridge test follows.
    auto created = pctl->Request(1, kCreateInput, true);
    Compare("pctl 1 CreateServiceWithoutInitialize", created, {0, {}, 1});
    if (created.objects.size() == 1) {
        auto& child = *created.objects[0];
        Compare("pctl child 1 Initialize", child.Request(1, {}, false), {0, {}, 0});
        ChildCalls("pctl child", child);
    }
    // CreateService initializes the child itself.
    auto initialized = pctl->Request(0, kCreateInput, true);
    Compare("pctl 0 CreateService", initialized, {0, {}, 1});
    if (initialized.objects.size() == 1)
        ChildCalls("pctl initialized child", *initialized.objects[0]);

    for (const char* port : {"pctl:s", "pctl:a", "pctl:r"}) {
        auto restricted = link->Connect(port, std::chrono::seconds(5));
        if (!restricted) {
            std::printf("FAIL %-44s could not connect\n", port);
            ++differences;
            continue;
        }
        const std::string name = port;
        auto opened = restricted->Request(1, kCreateInput, true);
        Compare((name + " 1 CreateServiceWithoutInitialize").c_str(), opened, {0, {}, 1});
        if (opened.objects.size() == 1)
            Compare((name + " child 1 Initialize").c_str(), opened.objects[0]->Request(1, {}, false), {kNoCapability, {}, 0});
        Compare((name + " 0 CreateService").c_str(), restricted->Request(0, kCreateInput, true), {kNoCapability, {}, 0});
    }
    // Not a comparison: the module's event from 1432 on a port whose sessions
    // have capability 0x8, which firmware requires for it and "pctl" lacks.
    // Only in normal boot (mode 0): in maintenance mode the module refuses it.
    if (auto system = link->Connect("pctl:s", std::chrono::seconds(5))) {
        auto opened = system->Request(1, kCreateInput, true);
        if (opened.objects.size() == 1 && opened.objects[0]->Request(1, {}, false).result == 0) {
            auto sync = opened.objects[0]->Request(1432, {}, false);
            std::printf("info pctl:s child 1432 (module only): result %08x, %zu event(s)%s\n", sync.result,
                        sync.events.size(),
                        sync.events.empty() ? "" : sync.events[0]->Signaled() ? ", signalled" : ", not signalled");
        }
    }
    std::printf("%d difference(s)\n", differences);
    return differences;
}
