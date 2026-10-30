// Services an application asks for, as hand-written stand-ins: the ones a
// title calls before its first frame (plan.md, phase 1). Hardware services
// stay native by design; the system-logic ones (am, ns, pctl and the rest)
// are placeholders until phase 2 recompiles them. Each answers only the
// commands a title has been seen to call; anything else is reported.
#pragma once

#include "native.h"

namespace services {

struct ApplicationOptions {
    uint64_t program_id = 0;
    bool trace = false;
};

// Adds the application services to host, replacing stubs of the same name.
void AddApplicationServices(NativeHost& host, const ApplicationOptions& options);

} // namespace services
