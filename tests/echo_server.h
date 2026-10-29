// An authored sysmodule-style server. It reaches the kernel only through
// hk_svc and its own guest memory, exactly as recompiled code would.
#pragma once

#include "guest.h"

namespace echo {

enum Command : uint32_t {
    Echo = 1,    // reply with the request's data words
    WhoAmI = 2,  // reply with the PID the kernel inserted
    OpenSub = 3, // create a session and move its client end back
    Adopt = 4,   // serve the server session moved in by the client
    Quit = 5,    // reply, then close every handle and return
    Stats = 6,   // reply with the number of handles the server holds
};

inline constexpr uint32_t MaxSessions = 4;

// Registers the "echo" port and serves until Quit. Returns the first
// unexpected kernel result, or Success.
hk::Result RunServer(hk_thread* thread, TestMemory& memory, uint64_t tls, uint64_t scratch);

} // namespace echo
