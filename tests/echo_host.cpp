// Runs the echo server as its own host process with its own kernel, linked
// to a parent over two inherited pipe handles: echo_host <read> <write>.
// Exits with 0 after a Quit, or with the server's failing result.
#include "echo_server.h"
#include "hk/link.h"

#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: echo_host <read handle> <write handle>\n");
        return 2;
    }
    const auto read_handle = static_cast<uintptr_t>(std::strtoull(argv[1], nullptr, 10));
    const auto write_handle = static_cast<uintptr_t>(std::strtoull(argv[2], nullptr, 10));

    constexpr uint64_t Base = 0x10000000, Pid = 0x51;
    FlatMemory memory(Base, 0x1000, echo::IpcArea);
    hk::Result result;
    {
        hk::Kernel kernel;
        auto process = kernel.CreateProcess(Pid, memory);
        hk_thread* thread = kernel.CreateThread(process, Base);
        kernel.AttachLink(hk::OpenPipeStream(read_handle, write_handle), false);
        result = echo::RunServer(thread, memory, Base, Base + 0x200);
        kernel.DestroyProcess(process);
    } // the kernel flushes queued frames before closing the link
    return static_cast<int>(result);
}
