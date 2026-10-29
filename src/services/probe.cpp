#include "probe.h"

#include "hk/native.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

namespace services {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;
constexpr uint64_t kName = kBase + 0x200;
constexpr uint64_t kProcessId = 0x80;
constexpr uint32_t kInMagic = 0x49434653, kOutMagic = 0x4F434653;

struct Reply {
    hk::Result kernel{};
    hk::Result result{};
    std::vector<uint32_t> raw;
    std::vector<uint32_t> move;
};

// One CMIF request: header, optional PID, CMIF header at the next 16-byte
// boundary, raw words.
Reply Call(hk_thread* thread, FlatMemory& memory, uint32_t session, uint32_t command, bool send_pid,
           std::vector<uint32_t> raw) {
    Message request;
    request.type = 4;
    request.send_pid = send_pid;
    const uint32_t data_word = 2 + (send_pid ? 3 : 0);
    // Clients always reserve 16 bytes for alignment, whatever part of it the
    // header's position uses; servers check the data size against that.
    const uint32_t pad = (4 - data_word % 4) % 4;
    request.data.assign(pad, 0);
    request.data.insert(request.data.end(), {kInMagic, 0, command, 0});
    request.data.insert(request.data.end(), raw.begin(), raw.end());
    request.data.insert(request.data.end(), 4 - pad, 0);
    WriteMessage(memory, kTls, request);
    Reply reply;
    reply.kernel = svc::SendSyncRequest(thread, session);
    if (reply.kernel)
        return reply;
    const Message message = ReadMessage(memory, kTls);
    reply.move = message.move;
    const uint32_t reply_word = 2 + (message.move.empty() && message.copy.empty() ? 0 : 1) +
                                static_cast<uint32_t>(message.move.size() + message.copy.size());
    const size_t reply_pad = (4 - reply_word % 4) % 4;
    if (message.data.size() < reply_pad + 4 || message.data[reply_pad] != kOutMagic) {
        reply.result = 0xffffffff;
        return reply;
    }
    reply.result = message.data[reply_pad + 2];
    reply.raw.assign(message.data.begin() + static_cast<ptrdiff_t>(reply_pad + 4), message.data.end());
    return reply;
}

void Probe(hk::Kernel& kernel) {
    auto memory = std::make_unique<FlatMemory>(kBase, 0x1000);
    auto process = kernel.CreateProcess(kProcessId, *memory);
    hk_thread* thread = kernel.CreateThread(process, kTls);
    memory->WriteString(kName, "pctl");

    uint32_t session = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    hk::Result r;
    while ((r = svc::ConnectToNamedPort(thread, kName, session)) == hk::result::NotFound &&
           std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (r) {
        std::fprintf(stderr, "probe: could not connect to pctl (%08x)\n", r);
        std::exit(5);
    }
    // Give the module time to finish start-up and enter its server loop.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const Reply created = Call(thread, *memory, session, 0, true, {0, 0}); // CreateService(reserved, pid)
    std::fprintf(stderr, "probe: pctl CreateService -> kernel %08x, result %08x, %zu moved handle(s)\n",
                 created.kernel, created.result, created.move.size());
    if (created.kernel || created.result || created.move.size() != 1)
        std::exit(6);

    const Reply restricted = Call(thread, *memory, created.move[0], 1403, false, {}); // IsRestrictionEnabled
    std::fprintf(stderr, "probe: IParentalControlService IsRestrictionEnabled -> kernel %08x, result %08x, value %u\n",
                 restricted.kernel, restricted.result, restricted.raw.empty() ? 0xffffffffu : restricted.raw[0] & 0xff);
    // Any result the module itself produced shows it is serving; whether the
    // value is right is for the comparison against the verified service.
    std::exit(restricted.kernel || restricted.result == 0xffffffff ? 7 : 0);
}

} // namespace

void StartPctlProbe(hk::Kernel& kernel) {
    std::thread([&kernel] { Probe(kernel); }).detach();
}

} // namespace services
