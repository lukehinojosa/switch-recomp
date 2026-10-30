// An authored sysmodule-style server. It reaches the kernel only through
// hk_svc and its own guest memory, exactly as recompiled code would.
#pragma once

#include "hk/native.h"

namespace echo {

enum Command : uint32_t {
    Echo = 1,    // reply with the request's data words
    WhoAmI = 2,  // reply with the PID the kernel inserted
    OpenSub = 3, // create a session and move its client end back
    Adopt = 4,   // serve the server session moved in by the client
    Quit = 5,    // reply, then close every handle and return
    Stats = 6,   // reply with the number of handles the server holds
    Buffers = 7, // takes X, A, B and W: writes B = A reversed, W = W + 1 per
                 // byte, replies with data {X size} and X reversed as an X
    GetEvent = 8,    // copy back the readable end of the server's event
    SignalIt = 9,    // signal the server's event
    ClearIt = 10,    // clear it
    IsSignaled = 11, // reply with {1} if the server sees it signalled, else {0}
};

// The server's receive list: one buffer every incoming X is packed into.
inline constexpr uint64_t ReceiveOffset = 0x800, ReceiveSize = 0x200;
// Server memories need an IPC mapping area of at least this size.
inline constexpr size_t IpcArea = 0x1000;

inline constexpr uint32_t MaxSessions = 4;

// Registers the "echo" port and serves until Quit. Returns the first
// unexpected kernel result, or Success.
hk::Result RunServer(hk_thread* thread, FlatMemory& memory, uint64_t tls, uint64_t scratch);

} // namespace echo
