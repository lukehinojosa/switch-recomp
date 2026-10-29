// Stub services for running a recompiled module on its own. Each answers
// only the commands a module has been seen to call, with the value a
// stand-alone console would give; anything else is reported as unknown.
#pragma once

#include "native.h"

namespace services {

struct StubOptions {
    // pm:bm GetBootMode: 0 normal, 1 maintenance.
    uint32_t boot_mode = 1;
    bool trace = false;
};

// Adds every stub to host.
void AddStubs(NativeHost& host, const StubOptions& options);

} // namespace services
