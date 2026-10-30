// Stub services for running a recompiled module on its own. Each answers
// only the commands a module has been seen to call, with the value a
// stand-alone console would give; anything else is reported as unknown.
#pragma once

#include "native.h"

#include <optional>

namespace services {

// An application process as arp registers it at launch.
struct Application {
    uint64_t process_id = 0;
    uint64_t program_id = 0;
    uint32_t version = 0;
    std::vector<std::byte> control; // its control.nacp
};

struct StubOptions {
    // pm:bm GetBootMode: 0 normal, 1 maintenance.
    uint32_t boot_mode = 1;
    // What arp:r reports as running; none means no process is an application.
    std::optional<Application> application;
    bool trace = false;
};

// Adds every stub to host.
void AddStubs(NativeHost& host, const StubOptions& options);

} // namespace services
