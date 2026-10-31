#include "probe.h"

#include "hk/native.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

namespace services {

namespace {

constexpr uint64_t kBase = 0x10000;
constexpr uint64_t kTls = kBase;
constexpr uint64_t kName = kBase + 0x200;
constexpr uint64_t kBuffer = kBase + 0x400; // the launcher's A buffers, up to 0xC00 bytes
constexpr uint64_t kProcessId = 0x80;
constexpr uint64_t kLauncherProcessId = 0x81;
constexpr uint32_t kInMagic = 0x49434653, kOutMagic = 0x4F434653;

struct Reply {
    hk::Result kernel{};
    hk::Result result{};
    std::vector<uint32_t> raw;
    std::vector<uint32_t> move;
};

// One CMIF request: header, optional PID, A buffers, CMIF header at the next
// 16-byte boundary, raw words.
Reply Call(hk_thread* thread, FlatMemory& memory, uint32_t session, uint32_t command, bool send_pid,
           std::vector<uint32_t> raw, std::vector<MappedBuffer> sends = {}) {
    Message request;
    request.type = 4;
    request.send_pid = send_pid;
    request.sends = std::move(sends);
    // Clients always reserve 16 bytes for alignment, whatever part of it the
    // header's position uses; servers check the data size against that.
    const uint32_t pad = CmifPadding(request);
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

    const Reply restricted = Call(thread, *memory, created.move[0], 1031, false, {}); // IsRestrictionEnabled
    std::fprintf(stderr, "probe: IParentalControlService IsRestrictionEnabled -> kernel %08x, result %08x, value %u\n",
                 restricted.kernel, restricted.result, restricted.raw.empty() ? 0xffffffffu : restricted.raw[0] & 0xff);
    // Any result the module itself produced shows it is serving; whether the
    // value is right is for the comparison against the verified service.
    std::exit(restricted.kernel || restricted.result == 0xffffffff ? 7 : 0);
}

uint64_t NameOf(const char* name) {
    uint64_t value = 0;
    std::memcpy(&value, name, std::min<size_t>(std::strlen(name), 8));
    return value;
}

// ns's application records, as an installer pushes them: for every
// application with content in the index's BuiltInUser storage, the content
// meta keys of the application, its patch and its add-on content.
std::map<uint64_t, std::vector<std::array<std::byte, 0x18>>> InstalledRecords(const std::string& content) {
    std::map<uint64_t, std::vector<std::array<std::byte, 0x18>>> records;
    const std::filesystem::path dir = std::filesystem::path(content) / "BuiltInUser";
    if (content.empty() || !std::filesystem::is_directory(dir))
        return records;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() != ".meta")
            continue;
        // <id>_<version>_<type>_<install type>.meta
        std::istringstream fields(entry.path().stem().string());
        std::string part[4];
        for (auto& p : part)
            std::getline(fields, p, '_');
        const uint64_t id = std::stoull(part[0], nullptr, 16);
        const auto version = static_cast<uint32_t>(std::stoul(part[1]));
        const auto type = static_cast<uint8_t>(std::stoul(part[2]));
        // The application a patch (0x81) or add-on content (0x82) belongs to.
        uint64_t application = id;
        if (type == 0x81)
            application = id & ~uint64_t{0x800};
        else if (type == 0x82)
            application = (id & ~uint64_t{0xFFF}) ^ 0x1000;
        else if (type != 0x80)
            continue;
        // ContentStorageRecord: the content meta key (id, version, type,
        // install type), then the storage id at 0x10.
        std::array<std::byte, 0x18> record{};
        std::memcpy(&record[0], &id, 8);
        std::memcpy(&record[8], &version, 4);
        record[0xC] = std::byte{type};
        record[0xD] = static_cast<std::byte>(std::stoul(part[3]));
        record[0x10] = std::byte{4}; // BuiltInUser
        records[application].push_back(record);
    }
    return records;
}

void Launch(hk::Kernel& kernel, uint64_t program_id, std::string content) {
    auto memory = std::make_unique<FlatMemory>(kBase, 0x1000);
    auto process = kernel.CreateProcess(kLauncherProcessId, *memory);
    hk_thread* thread = kernel.CreateThread(process, kTls);
    memory->WriteString(kName, "sm:");
    uint32_t sm = 0;
    if (const hk::Result r = svc::ConnectToNamedPort(thread, kName, sm)) {
        std::fprintf(stderr, "launch: could not connect to sm: (%08x)\n", r);
        return;
    }
    Call(thread, *memory, sm, 0, true, {0, 0}); // RegisterClient(reserved, pid)
    const uint64_t name = NameOf("ns:am2");
    // sm answers once ns has registered the port.
    const Reply service = Call(thread, *memory, sm, 1, false, {static_cast<uint32_t>(name), static_cast<uint32_t>(name >> 32)});
    if (service.kernel || service.result || service.move.size() != 1) {
        std::fprintf(stderr, "launch: no ns:am2 (kernel %08x, result %08x)\n", service.kernel, service.result);
        return;
    }
    // IServiceGetterInterface: GetApplicationManagerInterface (7996)
    const Reply manager = Call(thread, *memory, service.move[0], 7996, false, {});
    if (manager.kernel || manager.result || manager.move.size() != 1) {
        std::fprintf(stderr, "launch: no IApplicationManagerInterface (kernel %08x, result %08x)\n", manager.kernel,
                     manager.result);
        return;
    }
    const uint32_t applications = manager.move[0];
    // PushApplicationRecord (16): u8 event (3, installed), the application id
    // at 8, A the content storage records. ns keeps its records in a save,
    // which the host does not keep, so they are pushed at every start.
    for (const auto& [application, records] : InstalledRecords(content)) {
        std::vector<std::byte> bytes;
        for (const auto& record : records)
            bytes.insert(bytes.end(), record.begin(), record.end());
        if (bytes.size() > 0xC00)
            continue;
        memory->Write(kBuffer, bytes);
        const Reply pushed = Call(thread, *memory, applications, 16, false,
                                  {3, 0, static_cast<uint32_t>(application), static_cast<uint32_t>(application >> 32)},
                                  {{kBuffer, bytes.size()}});
        std::fprintf(stderr, "launch: PushApplicationRecord(%016llx, %zu contents) -> kernel %08x, result %08x\n",
                     static_cast<unsigned long long>(application), records.size(), pushed.kernel, pushed.result);
    }
    const std::vector<uint32_t> id{static_cast<uint32_t>(program_id), static_cast<uint32_t>(program_id >> 32)};
    // GetApplicationLaunchInfo (95): application id -> the 0x80-byte
    // ApplicationLaunchInfo (the id, its version, its storages).
    const Reply info = Call(thread, *memory, applications, 95, false, id);
    std::fprintf(stderr, "launch: GetApplicationLaunchInfo(%016llx) -> kernel %08x, result %08x\n",
                 static_cast<unsigned long long>(program_id), info.kernel, info.result);
    if (info.kernel || info.result || info.raw.size() < 0x20)
        return;
    for (size_t i = 0; i < 0x20; i += 4)
        std::fprintf(stderr, "launch:   info %02zx: %08x %08x %08x %08x\n", i * 4, info.raw[i], info.raw[i + 1],
                     info.raw[i + 2], info.raw[i + 3]);
    // LaunchApplication (94): u8 flags, then the launch info at 8 -> process
    // id. ns acquires the rights (es), registers the application (arp) and
    // calls pgl LaunchProgram, then keeps the launch info for am to acquire.
    std::vector<uint32_t> launch_info(info.raw.begin(), info.raw.begin() + 0x20);
    // CreateApplicationInstance (2517): the launch info -> the application
    // instance id, which the launch info carries at 0x30 from then on.
    const Reply instance = Call(thread, *memory, applications, 2517, false, launch_info);
    std::fprintf(stderr, "launch: CreateApplicationInstance -> kernel %08x, result %08x, instance %08x\n",
                 instance.kernel, instance.result, instance.raw.empty() ? 0 : instance.raw[0]);
    if (instance.kernel || instance.result || instance.raw.size() < 2)
        return;
    launch_info[0x30 / 4] = instance.raw[0];
    launch_info[0x34 / 4] = instance.raw[1];
    // 2513: the launch info -> process id, the launch for an instance created
    // first (the routine LaunchApplication, 94, enters without one).
    const Reply launched = Call(thread, *memory, applications, 2513, false, launch_info);
    std::fprintf(stderr, "launch: LaunchApplication -> kernel %08x, result %08x, process id %08x\n", launched.kernel,
                 launched.result, launched.raw.empty() ? 0 : launched.raw[0]);
    if (launched.kernel || launched.result)
        return;
    // AcquireApplicationLaunchInfo (96), as am does once the process is up.
    const Reply acquired = Call(thread, *memory, applications, 96, false, id);
    std::fprintf(stderr, "launch: AcquireApplicationLaunchInfo -> kernel %08x, result %08x\n", acquired.kernel,
                 acquired.result);
}

} // namespace

void StartLaunch(hk::Kernel& kernel, uint64_t program_id, std::string content) {
    std::thread([&kernel, program_id, content = std::move(content)] { Launch(kernel, program_id, content); }).detach();
}

void StartPctlProbe(hk::Kernel& kernel) {
    std::thread([&kernel] { Probe(kernel); }).detach();
}

} // namespace services
