// Round-trip cost of one IPC request: the echo server in the same kernel (one
// host process, another host thread) and in echo_host across a pipe link.
// With a module host, also a real recompiled module's command through
// module_client:
//
//   roundtrip_bench [<module_host.exe> <module.load.elf> <control.nacp> <command> <port>]
//
// Each case warms up, then times single requests and prints the median, the
// 99th percentile and the mean, in microseconds.
#include "client/module_link.h"
#include "echo_server.h"
#include "hk/link.h"

#include "linked_child.h"

#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr int Warmup = 1000, Samples = 20000;
constexpr uint64_t ServerBase = 0x10000000, ClientBase = 0x20000000;

void Report(const char* label, const std::function<bool()>& call) {
    for (int i = 0; i < Warmup; ++i)
        if (!call()) {
            std::printf("%-34s failed\n", label);
            return;
        }
    std::vector<double> us(Samples);
    for (auto& sample : us) {
        const auto start = std::chrono::steady_clock::now();
        call();
        sample = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
    }
    const double mean = std::accumulate(us.begin(), us.end(), 0.0) / us.size();
    std::sort(us.begin(), us.end());
    std::printf("%-34s median %7.2f us   p99 %7.2f us   mean %7.2f us\n", label, us[us.size() / 2],
                us[us.size() * 99 / 100], mean);
}

// A client process in kernel calling the echo port.
struct Client {
    Client(hk::Kernel& kernel) : kernel(kernel) {
        process = kernel.CreateProcess(0x7c, memory);
        thread = kernel.CreateThread(process, ClientBase);
    }
    ~Client() { kernel.DestroyProcess(process); }
    bool Connect() {
        memory.WriteString(ClientBase + 0x200, "echo");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        hk::Result r;
        while ((r = svc::ConnectToNamedPort(thread, ClientBase + 0x200, session)) == hk::result::NotFound &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return r == hk::result::Success;
    }
    bool Call(uint32_t command) {
        Message request;
        request.data = {command, 1, 2, 3};
        WriteMessage(memory, ClientBase, request);
        return svc::SendSyncRequest(thread, session) == hk::result::Success;
    }

    hk::Kernel& kernel;
    FlatMemory memory{ClientBase, 0x1000};
    std::shared_ptr<hk::Process> process;
    hk_thread* thread{};
    uint32_t session{};
};

void InProcess() {
    hk::Kernel kernel;
    FlatMemory server_memory(ServerBase, 0x1000, echo::IpcArea);
    auto server = kernel.CreateProcess(0x51, server_memory);
    hk_thread* server_thread = kernel.CreateThread(server, ServerBase);
    std::thread thread([&] { echo::RunServer(server_thread, server_memory, ServerBase, ServerBase + 0x200); });
    {
        Client client(kernel);
        if (client.Connect())
            Report("echo, same kernel", [&] { return client.Call(echo::Echo); });
        client.Call(echo::Quit);
    }
    thread.join();
    kernel.DestroyProcess(server);
}

void AcrossTheLink() {
    testing::LinkedChild host;
    if (!host.Start(testing::Beside("echo_host"))) {
        std::printf("%-34s could not start echo_host\n", "echo, across the link");
        return;
    }
    hk::Kernel kernel;
    kernel.AttachLink(host.TakeStream(), true);
    Client client(kernel);
    if (client.Connect())
        Report("echo, across the link", [&] { return client.Call(echo::Echo); });
    client.Call(echo::Quit);
    int code;
    host.Wait(10000, code);
}

void Module(char** argv) {
    client::ModuleOptions options;
    options.executable = argv[1];
    options.process_id = static_cast<uint64_t>(getpid());
    options.arguments = {"--application", std::to_string(options.process_id), "0100152000022000", "0", argv[3], argv[2]};
    const uint32_t command = static_cast<uint32_t>(std::stoul(argv[4]));
    try {
        auto link = client::ModuleLink::Start(options);
        auto port = link->Connect(argv[5], std::chrono::seconds(30));
        const std::byte create[8] = {};
        auto created = port ? port->Request(1, create, true) : client::Reply{};
        if (created.objects.size() != 1 || created.objects[0]->Request(1, {}, false).result) {
            std::printf("module: could not open a service on %s\n", argv[5]);
            return;
        }
        auto& service = *created.objects[0];
        const std::string label = std::string("module ") + argv[5] + " #" + argv[4] + ", linked";
        Report(label.c_str(), [&] {
            const auto reply = service.Request(command, {}, false);
            return reply.kernel == 0 && !reply.malformed;
        });
    } catch (const std::exception& error) {
        std::printf("module: %s\n", error.what());
    }
}

} // namespace

int main(int argc, char** argv) {
    InProcess();
    AcrossTheLink();
    if (argc >= 6)
        Module(argv);
}
