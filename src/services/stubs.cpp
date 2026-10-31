#include "stubs.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);
const hk::Result kTargetNotFound = MakeResult(2, 1002); // fs
const hk::Result kArpNotRegistered = MakeResult(157, 102);
const hk::Result kSettingsItemNotFound = MakeResult(105, 11);
const hk::Result kSplInvalidArgument = MakeResult(26, 101);
const hk::Result kProcessNotFound = MakeResult(15, 1); // pm
const hk::Result kProgramNotFound = MakeResult(8, 2); // lr: no such program
const hk::Result kTimeOutOfRange = MakeResult(116, 902); // time: not a calendar date
const hk::Result kNetworkUnavailable = MakeResult(110, 300); // nifm: no connection

// lm ILogger: accepts log packets and drops them.
class Logger final : public Interface {
public:
    const char* Name() const override { return "lm ILogger"; }
    hk::Result Handle(const Request& request, Response&) override {
        switch (request.command) {
        case 0: // Log(packet)
        case 1: // SetDestination(u32)
            return 0;
        default:
            return kUnknown;
        }
    }
};

// lm: ILogService.
class LogService final : public Interface {
public:
    const char* Name() const override { return "lm"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 0) // OpenLogger(pid) -> ILogger
            return kUnknown;
        response.objects.push_back(std::make_shared<Logger>());
        return 0;
    }
};

// pm:bm: IBootModeInterface.
class BootMode final : public Interface {
public:
    explicit BootMode(uint32_t mode) : mode_(mode) {}
    const char* Name() const override { return "pm:bm"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetBootMode -> u32
            response.Out(mode_);
            return 0;
        case 1: // SetMaintenanceBoot
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    uint32_t mode_;
};

// pm:info: IInformationInterface, over the host's process table.
class ProcessInformation final : public Interface {
public:
    explicit ProcessInformation(std::map<uint64_t, uint64_t> processes) : processes_(std::move(processes)) {}
    const char* Name() const override { return "pm:info"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // GetProgramId(u64 process id) -> u64
            auto it = processes_.find(request.In<uint64_t>(0));
            if (it == processes_.end())
                return kProcessNotFound;
            response.Out(it->second);
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    std::map<uint64_t, uint64_t> processes_;
};

// pgl IEventObserver: process events, of which there are none yet: the host
// starts no process after boot. Its event never signals.
class ShellEventObserver final : public Interface {
public:
    const char* Name() const override { return "pgl IEventObserver"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetProcessEventHandle -> copied event
            response.copy.push_back(request.create_event());
            return 0;
        case 1: // GetProcessEventInfo -> PmProcessEventInfo {u32 event, u64 process id}: none
            response.Out(std::array<uint64_t, 2>{});
            return 0;
        default:
            return kUnknown;
        }
    }
};

// pgl: IShellInterface, the program launcher, over TIPC: LaunchProgram,
// through the host, and its event observer.
class ProgramLauncher final : public Interface {
public:
    explicit ProgramLauncher(std::function<std::optional<uint64_t>(uint64_t)> launch) : launch_(std::move(launch)) {}
    const char* Name() const override { return "pgl"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // LaunchProgram(program location, u32 pm flags, u8 pgl flags) -> u64 process id
            // The location is the program id and a storage id; the host runs
            // what it was given, from wherever it is.
            const uint64_t program_id = request.In<uint64_t>(0);
            const auto process_id = launch_ ? launch_(program_id) : std::nullopt;
            if (!process_id)
                return kProgramNotFound;
            response.Out(*process_id);
            launched_ = *process_id;
            return 0;
        }
        case 5: // GetApplicationProcessId -> u64: the one launched, if any
            if (!launched_)
                return kProcessNotFound;
            response.Out(launched_);
            return 0;
        case 6:  // BoostSystemMemoryResourceLimit(u64 size): the host's memory is not partitioned
        case 8:  // EnableApplicationCrashReport(bool)
        case 10: // EnableApplicationAllThreadDumpOnCrash(bool)
            return 0;
        case 7: // IsApplicationTracking(program id) -> bool: no crash report tracks it
        case 9: // IsApplicationCrashReportEnabled -> bool
            response.Out(uint8_t{0});
            return 0;
        case 20: // GetShellEventObserver -> IEventObserver
            response.objects.push_back(std::make_shared<ShellEventObserver>());
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::function<std::optional<uint64_t>(uint64_t)> launch_;
    uint64_t launched_ = 0;
};

// ovln:snd ISender: accepts overlay notifications and drops them.
class OverlaySender final : public Interface {
public:
    const char* Name() const override { return "ovln ISender"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // Send(notification)
            return 0;
        case 1: // GetUnreceivedMessageCount -> u32
            response.Out(uint32_t{0});
            return 0;
        default:
            return kUnknown;
        }
    }
};

// ovln:snd: ISenderService.
class OverlaySenderService final : public Interface {
public:
    const char* Name() const override { return "ovln:snd"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 0) // OpenSender(queue size, ...) -> ISender
            return kUnknown;
        response.objects.push_back(std::make_shared<OverlaySender>());
        return 0;
    }
};

// A service that only matters with a network, which is down: commands that
// return an event get one that never fires, those that return an object get
// another quiet one (which gives an event from command 0, as progress and
// notifier objects do), every other command succeeds with zeroed output.
// Each command is logged when tracing.
class Quiet final : public Interface {
public:
    Quiet(std::string name, std::vector<uint32_t> event_commands, bool trace,
          std::vector<uint32_t> object_commands = {})
        : name_(std::move(name)), events_(std::move(event_commands)), objects_(std::move(object_commands)),
          trace_(trace) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request& request, Response& response) override {
        if (trace_)
            std::fprintf(stderr, "%s: command %u accepted%c", name_.c_str(), request.command, 10);
        const auto has = [&](const std::vector<uint32_t>& commands) {
            return std::find(commands.begin(), commands.end(), request.command) != commands.end();
        };
        if (has(events_))
            response.copy.push_back(request.create_event());
        else if (has(objects_))
            response.objects.push_back(std::make_shared<Quiet>(name_ + " object", std::vector<uint32_t>{0}, trace_));
        else
            response.Out(std::array<uint64_t, 2>{});
        return 0;
    }

private:
    std::string name_;
    std::vector<uint32_t> events_, objects_;
    bool trace_;
};

// arp IRegistrar: what ns registers for an application it launches. Issue
// (0) gives the instance id, 1, as arp:r reports it; the other commands are
// accepted and logged when tracing.
class ApplicationRegistrar final : public Interface {
public:
    explicit ApplicationRegistrar(bool trace) : trace_(trace) {}
    const char* Name() const override { return "arp IRegistrar"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (trace_)
            std::fprintf(stderr, "arp: registrar command %u, %zu bytes, %zu buffers\n", request.command,
                         request.raw.size(), request.sends.size() + request.statics.size());
        if (request.command == 0) // Issue -> instance id
            response.Out(uint64_t{1});
        return 0;
    }

private:
    bool trace_;
};

// arp:w: IWriter. AcquireRegistrar (0) gives a registrar.
class ApplicationWriter final : public Interface {
public:
    explicit ApplicationWriter(bool trace) : trace_(trace) {}
    const char* Name() const override { return "arp:w"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (trace_)
            std::fprintf(stderr, "arp: writer command %u, %zu bytes\n", request.command, request.raw.size());
        if (request.command != 0)
            return kUnknown;
        response.objects.push_back(std::make_shared<ApplicationRegistrar>(trace_));
        return 0;
    }

private:
    bool trace_;
};

// arp:r: IReader. Reports the one application in the options, if any; every
// other process is unregistered, as a system process such as a test client is.
class ApplicationReader final : public Interface {
public:
    explicit ApplicationReader(std::optional<Application> application) : application_(std::move(application)) {}
    const char* Name() const override { return "arp:r"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetApplicationLaunchProperty(pid) -> ApplicationLaunchProperty
        case 1: // GetApplicationLaunchPropertyWithApplicationId(application id)
            if (!Matches(request))
                return kArpNotRegistered;
            response.Out(application_->program_id);
            response.Out(application_->version);
            response.Out(uint32_t{0x0505}); // base and patch storage: SD card (5); kind: application (0)
            return 0;
        case 3: // newer: GetApplicationInstanceId(pid) -> instance id
            if (application_ && request.In<uint64_t>(0) == application_->process_id) {
                response.Out(kInstanceId);
                return 0;
            }
            [[fallthrough]]; // older: GetApplicationControlPropertyWithApplicationId(application id) -> B
        case 2: // GetApplicationControlProperty(pid) -> B
            if (!Matches(request))
                return kArpNotRegistered;
            return request.OutBuffer(application_->control) ? 0 : kUnknown;
        case 4: // GetApplicationInstanceUnregistrationNotifier -> IUnregistrationNotifier
            // GetReadableHandle (0) gives an event that never fires: the
            // application stays registered while the host runs.
            response.objects.push_back(std::make_shared<Quiet>("arp IUnregistrationNotifier", std::vector<uint32_t>{0}, false));
            return 0;
        case 5: { // ListApplicationInstanceId -> s32 count, B instance ids
            const bool listed = application_ && !request.receives.empty() && request.receives[0].size >= 8;
            if (listed) {
                std::array<std::byte, 8> id;
                std::memcpy(id.data(), &kInstanceId, 8);
                request.OutBuffer(id);
            }
            response.Out(int32_t{listed ? 1 : 0});
            return 0;
        }
        case 6: // GetApplicationInstanceId(pid) -> instance id (libnx's numbering; pctl sends a PID)
            if (!application_ || request.In<uint64_t>(0) != application_->process_id)
                return kArpNotRegistered;
            response.Out(kInstanceId);
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    // The first application launched since boot. Newer firmware names the
    // application by this instance id where older took its process id.
    static constexpr uint64_t kInstanceId = 1;

    bool Matches(const Request& request) const {
        if (!application_)
            return false;
        const auto key = request.In<uint64_t>(0);
        if (key == kInstanceId)
            return true;
        return request.command % 2 == 0 ? key == application_->process_id : key == application_->program_id;
    }
    std::optional<Application> application_;
};

// bsd:s: IClient. There is no network: clients register, and every socket
// operation fails with ENETDOWN, which callers treat as being offline.
class Sockets final : public Interface {
public:
    const char* Name() const override { return "bsd:s"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0:  // RegisterClient(config, pid, transfer memory size, transfer memory) -> i32
        case 33: // the same, in newer firmware's clients
            response.Out(int32_t{0});
            return 0;
        case 1: // StartMonitoring(pid)
            return 0;
        default:
            if (request.command < 2 || request.command > 32)
                return kUnknown;
            response.Out(int32_t{-1}); // return value
            response.Out(kEnetdown);   // errno
            return 0;
        }
    }

private:
    static constexpr uint32_t kEnetdown = 50;
};

// nifm IRequest: a request for a connection that is never granted. Its
// settings are accepted; it stays free and its events never signal.
class NetworkRequest final : public Interface {
public:
    const char* Name() const override { return "nifm IRequest"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetRequestState -> u32: free
            response.Out(uint32_t{1});
            return 0;
        case 1: // GetResult: no connection
            return kNetworkUnavailable;
        case 2: // GetSystemEventReadableHandles -> two copied events
            response.copy.push_back(request.create_event());
            response.copy.push_back(request.create_event());
            return 0;
        case 3: // Cancel
        case 4: // Submit
            return 0;
        default:
            if (request.command >= 5 && request.command <= 25) // setters
                return 0;
            return kUnknown;
        }
    }
};

// nifm IGeneralService: no network interface is up.
class NetworkGeneral final : public Interface {
public:
    const char* Name() const override { return "nifm IGeneralService"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 4: // CreateRequest(u32 requirement preset) -> IRequest
            response.objects.push_back(std::make_shared<NetworkRequest>());
            return 0;
        case 6: { // EnumerateNetworkInterfaces(u32 filter) -> B infos, s32 count
            // One wireless interface, down. An entry is the type (1:
            // IEEE 802.11), the MAC address and a flag; the address is a
            // fixed, locally administered one, like spl:'s device id.
            const std::array<uint8_t, 8> wireless{1, 0x02, 0x48, 0x4F, 0x53, 0x54, 0x31, 0};
            if (!(request.In<uint32_t>(0) & 1) || !request.OutBuffer(std::as_bytes(std::span(wireless)))) {
                response.Out(int32_t{0});
                return 0;
            }
            response.Out(int32_t{1});
            return 0;
        }
        default:
            return kUnknown;
        }
    }
};

// nifm:s: IStaticService.
class NetworkStatic final : public Interface {
public:
    const char* Name() const override { return "nifm:s"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 4: // CreateGeneralServiceOld
        case 5: // CreateGeneralService(reserved, pid)
            response.objects.push_back(std::make_shared<NetworkGeneral>());
            return 0;
        default:
            return kUnknown;
        }
    }
};

// time: every clock reads the host's clock, as on a console whose clocks are
// set and synced.
int64_t PosixNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A clock's source: a fixed id, standing for this boot's steady clock.
constexpr uint8_t kClockSourceId[16] = {0x73, 0x77, 0x72, 0x63, 0x6c, 0x6f, 0x63, 0x6b,
                                        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

int64_t SteadySeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// SteadyClockTimePoint: seconds, then the source id.
void OutTimePoint(Response& response, int64_t seconds) {
    response.Out(seconds);
    for (uint8_t b : kClockSourceId)
        response.Out(b);
}

class SystemClock final : public Interface {
public:
    const char* Name() const override { return "time ISystemClock"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetCurrentTime -> i64
            response.Out(PosixNow());
            return 0;
        case 1: // SetCurrentTime
        case 3: // SetSystemClockContext
            return 0;
        case 2: // GetSystemClockContext -> {i64 offset, time point}
            response.Out(PosixNow() - SteadySeconds());
            OutTimePoint(response, SteadySeconds());
            return 0;
        default:
            return kUnknown;
        }
    }
};

class SteadyClock final : public Interface {
public:
    const char* Name() const override { return "time ISteadyClock"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetCurrentTimePoint -> SteadyClockTimePoint
            OutTimePoint(response, SteadySeconds());
            return 0;
        case 2: // GetTestOffset -> i64
        case 100: // GetRtcValue -> i64
        case 200: // GetInternalOffset -> i64
            response.Out(int64_t{0});
            return 0;
        default:
            return kUnknown;
        }
    }
};

// time ITimeZoneService: the device is in UTC.
class TimeZone final : public Interface {
public:
    const char* Name() const override { return "time ITimeZoneService"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // GetDeviceLocationName -> LocationName (36 bytes)
            char name[36] = "UTC";
            for (char ch : name)
                response.Out(ch);
            return 0;
        }
        case 1: // SetDeviceLocationName
            return 0;
        case 20: // GetDeviceLocationNameOperationEventReadableHandle
            response.copy.push_back(request.create_event());
            return 0;
        case 2: // GetTotalLocationNameCount -> u32
            response.Out(uint32_t{1});
            return 0;
        case 202: { // ToPosixTimeWithMyRule(CalendarTime) -> s32 count, C posix times: one, in UTC
            const std::chrono::year_month_day date{std::chrono::year(request.In<int16_t>(0)),
                                                   std::chrono::month(request.In<uint8_t>(2)),
                                                   std::chrono::day(request.In<uint8_t>(3))};
            if (!date.ok())
                return kTimeOutOfRange;
            const int64_t posix = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::sys_days(date).time_since_epoch()).count() +
                                  request.In<int8_t>(4) * 3600 + request.In<int8_t>(5) * 60 + request.In<int8_t>(6);
            request.OutBuffer(std::as_bytes(std::span(&posix, 1)));
            response.Out(int32_t{1});
            return 0;
        }
        case 101: { // ToCalendarTimeWithMyRule(posix time) -> CalendarTime, CalendarAdditionalInfo
            const int64_t posix = request.In<int64_t>(0);
            const auto days = std::chrono::sys_days(std::chrono::floor<std::chrono::days>(std::chrono::sys_seconds(std::chrono::seconds(posix))));
            const std::chrono::year_month_day date(days);
            const int64_t of_day = posix - std::chrono::duration_cast<std::chrono::seconds>(days.time_since_epoch()).count();
            response.Out(static_cast<int16_t>(static_cast<int>(date.year())));
            response.Out(static_cast<int8_t>(static_cast<unsigned>(date.month())));
            response.Out(static_cast<int8_t>(static_cast<unsigned>(date.day())));
            response.Out(static_cast<int8_t>(of_day / 3600));
            response.Out(static_cast<int8_t>(of_day / 60 % 60));
            response.Out(static_cast<int8_t>(of_day % 60));
            response.Out(int8_t{0});
            const auto year_start = std::chrono::sys_days(date.year() / std::chrono::January / 1);
            response.Out(static_cast<uint32_t>(std::chrono::weekday(days).c_encoding())); // day of week
            response.Out(static_cast<uint32_t>((days - year_start).count()));            // day of year
            const char zone[8] = "UTC";
            for (char ch : zone)
                response.Out(ch);
            response.Out(uint32_t{0}); // daylight saving
            response.Out(int32_t{0});  // offset from UTC, seconds
            return 0;
        }
        case 201: { // ToPosixTimeWithMyRule(CalendarTime) -> count, posix times (B)
            const auto year = request.In<int16_t>(0);
            const auto month = request.In<int8_t>(2), day = request.In<int8_t>(3);
            const auto hour = request.In<int8_t>(4), minute = request.In<int8_t>(5), second = request.In<int8_t>(6);
            const auto days = std::chrono::sys_days(std::chrono::year(year) / std::chrono::month(static_cast<unsigned>(month)) /
                                                    std::chrono::day(static_cast<unsigned>(day)));
            const int64_t posix = std::chrono::duration_cast<std::chrono::seconds>(days.time_since_epoch()).count() +
                                  hour * 3600 + minute * 60 + second;
            request.OutBuffer(std::as_bytes(std::span(&posix, 1)));
            response.Out(uint32_t{1});
            return 0;
        }
        default:
            return kUnknown;
        }
    }
};

// The time service's shared memory: each block is a counter and two copies
// of a context; readers take copy (counter & 1). Steady clock context at
// 0x00, local and network system clock contexts at 0x38 and 0x80, automatic
// correction at 0xc8, and the steady clock's continuous adjustment at 0xd0
// (copies of 0x38 bytes: base, multiplier, shift, then a system clock
// context). An adjustment of all zeros keeps the steady clock as it is; it
// needs only the clock source id. A snapshot is enough: the contexts are
// offsets that stay valid as the guest's tick counter advances.
std::vector<std::byte> SharedClockContexts() {
    std::vector<std::byte> page(0x1000);
    auto put = [&](size_t at, const void* data, size_t size) { std::memcpy(page.data() + at, data, size); };
    for (size_t copy = 0; copy < 2; ++copy) {
        const int64_t internal_offset = 0;
        put(0x08 + copy * 0x18, &internal_offset, 8);
        put(0x10 + copy * 0x18, kClockSourceId, 16);
        const int64_t offset = PosixNow() - SteadySeconds(), point = SteadySeconds();
        for (size_t block : {size_t{0x38}, size_t{0x80}}) {
            put(block + 0x08 + copy * 0x20, &offset, 8);
            put(block + 0x10 + copy * 0x20, &point, 8);
            put(block + 0x18 + copy * 0x20, kClockSourceId, 16);
        }
        page[0xc8 + 0x08 + copy] = std::byte{1};
        put(0xd8 + copy * 0x38 + 0x28, kClockSourceId, 16);
    }
    return page;
}

// time:u: IStaticService.
class TimeService final : public Interface {
public:
    const char* Name() const override { return "time:u"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // GetStandardUserSystemClock
        case 1: // GetStandardNetworkSystemClock
        case 4: // GetStandardLocalSystemClock
        case 5: // GetEphemeralNetworkSystemClock
            response.objects.push_back(std::make_shared<SystemClock>());
            return 0;
        case 2: // GetStandardSteadyClock
            response.objects.push_back(std::make_shared<SteadyClock>());
            return 0;
        case 3: // GetTimeZoneService
            response.objects.push_back(std::make_shared<TimeZone>());
            return 0;
        case 20: // GetSharedMemoryNativeHandle -> copied shared memory
            response.copy.push_back(request.create_shared_memory(SharedClockContexts()));
            return 0;
        case 100: // IsStandardUserSystemClockAutomaticCorrectionEnabled -> bool
        case 101: // IsStandardNetworkSystemClockAccuracySufficient -> bool
            response.Out(uint8_t{1});
            return 0;
        case 300: // CalculateMonotonicSystemClockBaseTimePoint(context) -> i64
            // The context's offset plus the steady clock's now, less the
            // tick counter's seconds: the two count from the same moment
            // here, so the offset alone.
            response.Out(request.In<int64_t>(0));
            return 0;
        default:
            return kUnknown;
        }
    }
};

// ssl:s: ISslService. Contexts are refused: there is no network to use them.
class SslService final : public Interface {
public:
    const char* Name() const override { return "ssl:s"; }
    hk::Result Handle(const Request& request, Response&) override {
        switch (request.command) {
        case 5: // SetInterfaceVersion(u32)
            return 0;
        default:
            return kUnknown;
        }
    }
};

// A NUL-terminated string argument in buffer index.
std::string StringArgument(const Request& request, size_t index) {
    std::string text;
    for (std::byte b : request.InBuffer(index)) {
        if (b == std::byte{0})
            break;
        text.push_back(static_cast<char>(b));
    }
    return text;
}

// set:sys: ISystemSettingsServer. Settings items come from a table of the
// values a console ships with; anything else is reported.
class SystemSettings final : public Interface {
    // Values assumed for a retail console; each was requested by a module.
    static const std::vector<std::byte>* Find(const std::string& item) {
        static const std::map<std::string, std::vector<std::byte>> items{
            {"pctl!ignore_post_event_interval_from_server", {std::byte{0}}},
        };
        auto it = items.find(item);
        return it == items.end() ? nullptr : &it->second;
    }

public:
    const char* Name() const override { return "set:sys"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 37:   // GetSettingsItemValueSize(name, key) -> u64
        case 38: { // GetSettingsItemValue(name, key) -> u64 size, B
            const std::string name = StringArgument(request, 0), key = StringArgument(request, 1);
            if (const auto* value = Find(name + "!" + key)) {
                if (request.command == 38)
                    request.OutBuffer(*value);
                response.Out(static_cast<uint64_t>(value->size()));
                return 0;
            }
            std::fprintf(stderr, "set:sys: item %s!%s not known\n", name.c_str(), key.c_str());
            return kSettingsItemNotFound;
        }
        case 62: // GetDebugModeFlag -> u32: a retail console
            response.Out(uint32_t{0});
            return 0;
        case 183: // GetPlatformRegion -> u32: global
            response.Out(uint32_t{1});
            return 0;
        default:
            return kUnknown;
        }
    }
};

// psc:m IPmModule: the console never changes power state.
class PowerModule final : public Interface {
public:
    const char* Name() const override { return "psc IPmModule"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: // Initialize(module id, dependencies) -> state change event
            response.copy.push_back(request.create_event());
            return 0;
        case 1: // GetRequest -> u32 state, u32 flags
            response.Out(uint32_t{0});
            response.Out(uint32_t{0});
            return 0;
        case 2: // Acknowledge
        case 3: // Finalize
        case 4: // AcknowledgeEx(state)
            return 0;
        default:
            return kUnknown;
        }
    }
};

// psc:m: IPmService.
class PowerService final : public Interface {
public:
    const char* Name() const override { return "psc:m"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 0) // GetPmModule -> IPmModule
            return kUnknown;
        response.objects.push_back(std::make_shared<PowerModule>());
        return 0;
    }
};

// IDeliveryCacheProgressService: a bcat request that is already done, as
// one with nothing to deliver is. GetEvent (0) is signalled; GetImpl (1)
// reports status 9 (done) and success.
class BcatProgress final : public Interface {
public:
    const char* Name() const override { return "bcat IDeliveryCacheProgressService"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // GetEvent -> copied event
            const auto [writable, readable] = request.create_event_pair();
            request.signal_event(writable);
            response.copy.push_back(readable);
            return 0;
        }
        case 1: { // GetImpl -> B DeliveryCacheProgressImpl (0x200 bytes)
            std::vector<std::byte> impl(0x200);
            const int32_t done = 9;
            std::memcpy(impl.data(), &done, sizeof done);
            return request.OutBuffer(impl) ? 0 : kUnknown;
        }
        default:
            return kUnknown;
        }
    }
};

// IBcatService: sync and suspension requests (10100, 10101, 20100, 20101,
// 20301) give requests that are already done; the update notifier (20300)
// is a quiet object. There is never anything to deliver.
class BcatService final : public Interface {
public:
    explicit BcatService(bool trace) : quiet_("bcat IBcatService", {}, trace, {20300}) {}
    const char* Name() const override { return "bcat IBcatService"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 10100: case 10101: case 20100: case 20101: case 20301:
            response.objects.push_back(std::make_shared<BcatProgress>());
            return 0;
        default:
            return quiet_.Handle(request, response);
        }
    }

private:
    Quiet quiet_;
};

// bcat:u, bcat:s: CreateBcatService (0) gives an IBcatService.
class Bcat final : public Interface {
public:
    Bcat(std::string name, bool trace) : name_(std::move(name)), trace_(trace) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 0)
            return kUnknown;
        response.objects.push_back(std::make_shared<BcatService>(trace_));
        return 0;
    }

private:
    std::string name_;
    bool trace_;
};

// npns:s: notifications, which never arrive. GetReceiveEvent (5),
// GetStateChangeEvent (7) and 40 give events; CreateNotificationReceiver (120)
// gives a receiver that accepts everything, with an event from command 4.
class NotificationSystem final : public Interface {
public:
    explicit NotificationSystem(bool trace) : quiet_("npns:s", {5, 7, 40}, trace), trace_(trace) {}
    const char* Name() const override { return "npns:s"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command == 120) {
            response.objects.push_back(
                std::make_shared<Quiet>("npns INotificationReceiver", std::vector<uint32_t>{4}, trace_));
            return 0;
        }
        return quiet_.Handle(request, response);
    }

private:
    Quiet quiet_;
    bool trace_;
};

// srepo:u: system reports, which go nowhere. Command 13005 gives the buffer
// they are written to: shared memory, with its size, the offset of the part
// in use and that part's length (16 KB here, a size of the host's choosing).
class SystemReports final : public Interface {
public:
    explicit SystemReports(bool trace) : quiet_("srepo:u", {}, trace) {}
    const char* Name() const override { return "srepo:u"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 13005)
            return quiet_.Handle(request, response);
        constexpr uint32_t kSize = 0x4000;
        response.copy.push_back(request.create_shared_memory(std::vector<std::byte>(kSize)));
        response.Out(std::array<uint32_t, 3>{kSize, 0, kSize});
        return 0;
    }

private:
    Quiet quiet_;
};

// bgtc:t: opens the background task interfaces (command 100, the task
// service; 101, state control), which behave as Quiet.
class BackgroundTaskFactory final : public Interface {
public:
    explicit BackgroundTaskFactory(bool trace) : trace_(trace) {}
    const char* Name() const override { return "bgtc:t"; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command != 100 && request.command != 101)
            return kUnknown;
        // ITaskService: GetTriggerEvent (3), GetScheduleEvent (14).
        response.objects.push_back(std::make_shared<Quiet>(
            request.command == 100 ? "bgtc ITaskService" : "bgtc IStateControlService",
            request.command == 100 ? std::vector<uint32_t>{3, 14} : std::vector<uint32_t>{}, trace_));
        return 0;
    }

private:
    bool trace_;
};

// A service that is registered but implements nothing yet: every command is
// reported, so a run shows what a module needs from it.
class Placeholder final : public Interface {
public:
    explicit Placeholder(std::string name) : name_(std::move(name)) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request&, Response&) override { return kUnknown; }

private:
    std::string name_;
};

const hk::Result kPathNotFound = MakeResult(2, 1);
const hk::Result kPathAlreadyExists = MakeResult(2, 2);
const hk::Result kDirectoryNotEmpty = MakeResult(2, 6007);
const hk::Result kOutOfRange = MakeResult(2, 3005);
const hk::Result kFsInvalidArgument = MakeResult(2, 6001);

// A save data file system held in memory. A fresh console has no saves, so
// a module creates what it needs; nothing outlives the host.
struct MemoryFileSystem {
    int64_t size{}, journal_size{}; // as created or last extended
    std::map<std::string, std::vector<std::byte>> files;
    std::set<std::string> directories{"/"};

    static std::string Parent(const std::string& path) {
        const size_t slash = path.find_last_of('/');
        return slash == 0 || slash == std::string::npos ? "/" : path.substr(0, slash);
    }
    bool Exists(const std::string& path) const { return files.contains(path) || directories.contains(path); }
};

// The path argument: an X (or A) buffer holding a NUL-terminated string.
std::string PathOf(const Request& request, size_t index = 0) {
    const auto bytes = request.InBuffer(index);
    std::string path;
    for (std::byte b : bytes) {
        if (b == std::byte{0})
            break;
        path.push_back(static_cast<char>(b));
    }
    while (path.size() > 1 && path.back() == '/')
        path.pop_back();
    return path.empty() ? "/" : path;
}

class File final : public Interface {
public:
    File(std::shared_ptr<MemoryFileSystem> fs, std::string path) : fs_(std::move(fs)), path_(std::move(path)) {}
    const char* Name() const override { return "fs IFile"; }
    hk::Result Handle(const Request& request, Response& response) override {
        auto it = fs_->files.find(path_);
        if (it == fs_->files.end())
            return kPathNotFound;
        auto& data = it->second;
        switch (request.command) {
        case 0: { // Read(option, offset, size) -> B, u64 read
            const auto offset = request.In<uint64_t>(8), size = request.In<uint64_t>(16);
            const uint64_t count = offset >= data.size() ? 0 : std::min<uint64_t>(size, data.size() - offset);
            if (count && !request.OutBuffer(std::span(data).subspan(offset, count)))
                return kOutOfRange;
            response.Out(count);
            return 0;
        }
        case 1: { // Write(option, offset, size) <- A
            const auto offset = request.In<uint64_t>(8), size = request.In<uint64_t>(16);
            const auto bytes = request.InBuffer(0);
            if (bytes.size() < size)
                return kOutOfRange;
            if (data.size() < offset + size)
                data.resize(offset + size);
            std::copy(bytes.begin(), bytes.begin() + static_cast<ptrdiff_t>(size), data.begin() + offset);
            return 0;
        }
        case 2: // Flush
            return 0;
        case 3: // SetSize(size)
            data.resize(request.In<uint64_t>(0));
            return 0;
        case 4: // GetSize -> u64
            response.Out(static_cast<uint64_t>(data.size()));
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<MemoryFileSystem> fs_;
    std::string path_;
};

// IDirectory: the entries directly under a directory, as they were when it
// was opened. Each is a DirectoryEntry: a NUL-terminated name in 0x301
// bytes, the type at 0x304 (0 directory, 1 file), the size at 0x308.
class Directory final : public Interface {
public:
    Directory(const MemoryFileSystem& fs, const std::string& path, uint32_t mode) {
        const std::string prefix = path == "/" ? "/" : path + "/";
        const auto add = [&](const std::string& entry, uint8_t type, int64_t size) {
            if (entry.size() <= prefix.size() || entry.compare(0, prefix.size(), prefix) != 0 ||
                entry.find('/', prefix.size()) != std::string::npos)
                return;
            std::array<std::byte, 0x310> bytes{};
            const std::string name = entry.substr(prefix.size(), 0x300);
            std::memcpy(bytes.data(), name.data(), name.size());
            bytes[0x304] = std::byte{type};
            std::memcpy(&bytes[0x308], &size, sizeof size);
            entries_.push_back(bytes);
        };
        if (mode & 1)
            for (const auto& directory : fs.directories)
                add(directory, 0, 0);
        if (mode & 2)
            for (const auto& [file, data] : fs.files)
                add(file, 1, static_cast<int64_t>(data.size()));
    }
    const char* Name() const override { return "fs IDirectory"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // Read -> u64 count, B entries
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x310;
            const size_t count = std::min(capacity, entries_.size() - next_);
            std::vector<std::byte> out;
            for (size_t i = 0; i < count; ++i)
                out.insert(out.end(), entries_[next_ + i].begin(), entries_[next_ + i].end());
            next_ += count;
            if (!out.empty() && !request.OutBuffer(out))
                return kOutOfRange;
            response.Out(static_cast<int64_t>(count));
            return 0;
        }
        case 1: // GetEntryCount -> u64
            response.Out(static_cast<int64_t>(entries_.size()));
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::vector<std::array<std::byte, 0x310>> entries_;
    size_t next_ = 0;
};

class FileSystem final : public Interface {
public:
    explicit FileSystem(std::shared_ptr<MemoryFileSystem> fs) : fs_(std::move(fs)) {}
    const char* Name() const override { return "fs IFileSystem"; }
    hk::Result Handle(const Request& request, Response& response) override {
        const std::string path = PathOf(request);
        auto& fs = *fs_;
        switch (request.command) {
        case 0: // CreateFile(option, size, path)
            if (fs.Exists(path))
                return kPathAlreadyExists;
            if (!fs.directories.contains(MemoryFileSystem::Parent(path)))
                return kPathNotFound;
            fs.files[path].resize(request.In<uint64_t>(8));
            return 0;
        case 1: // DeleteFile(path)
            return fs.files.erase(path) ? 0 : kPathNotFound;
        case 2: // CreateDirectory(path)
            if (fs.Exists(path))
                return kPathAlreadyExists;
            if (!fs.directories.contains(MemoryFileSystem::Parent(path)))
                return kPathNotFound;
            fs.directories.insert(path);
            return 0;
        case 3: // DeleteDirectory(path): must be empty
        case 4: // DeleteDirectoryRecursively(path)
        case 13: { // CleanDirectoryRecursively(path): delete the contents only
            if (!fs.directories.contains(path))
                return kPathNotFound;
            const std::string prefix = path == "/" ? "/" : path + "/";
            auto inside = [&](const std::string& p) { return p.compare(0, prefix.size(), prefix) == 0; };
            const bool empty = std::none_of(fs.files.begin(), fs.files.end(), [&](const auto& f) { return inside(f.first); }) &&
                               std::none_of(fs.directories.begin(), fs.directories.end(), inside);
            if (request.command == 3 && !empty)
                return kDirectoryNotEmpty;
            std::erase_if(fs.files, [&](const auto& f) { return inside(f.first); });
            std::erase_if(fs.directories, inside);
            if (request.command != 13 && path != "/")
                fs.directories.erase(path);
            return 0;
        }
        case 5:   // RenameFile(old path, new path)
        case 6: { // RenameDirectory(old path, new path)
            const std::string to = PathOf(request, 1);
            const bool file = request.command == 5;
            if (file ? !fs.files.contains(path) : !fs.directories.contains(path))
                return kPathNotFound;
            if (fs.Exists(to))
                return kPathAlreadyExists;
            if (!fs.directories.contains(MemoryFileSystem::Parent(to)))
                return kPathNotFound;
            if (file) {
                fs.files[to] = std::move(fs.files[path]);
                fs.files.erase(path);
                return 0;
            }
            // A directory takes everything under it along.
            const std::string prefix = path + "/";
            std::map<std::string, std::vector<std::byte>> files;
            for (auto it = fs.files.begin(); it != fs.files.end();) {
                if (it->first.compare(0, prefix.size(), prefix) == 0) {
                    files[to + it->first.substr(path.size())] = std::move(it->second);
                    it = fs.files.erase(it);
                } else {
                    ++it;
                }
            }
            fs.files.merge(files);
            std::set<std::string> directories{to};
            for (auto it = fs.directories.begin(); it != fs.directories.end();) {
                if (*it == path || it->compare(0, prefix.size(), prefix) == 0) {
                    if (*it != path)
                        directories.insert(to + it->substr(path.size()));
                    it = fs.directories.erase(it);
                } else {
                    ++it;
                }
            }
            fs.directories.merge(directories);
            return 0;
        }
        case 7: // GetEntryType(path) -> u32: 0 directory, 1 file
            if (!fs.Exists(path))
                return kPathNotFound;
            response.Out(static_cast<uint32_t>(fs.files.contains(path) ? 1 : 0));
            return 0;
        case 8: // OpenFile(mode, path) -> IFile
            if (!fs.files.contains(path))
                return kPathNotFound;
            response.objects.push_back(std::make_shared<File>(fs_, path));
            return 0;
        case 9: // OpenDirectory(u32 mode, path) -> IDirectory
            if (!fs.directories.contains(path))
                return kPathNotFound;
            response.objects.push_back(std::make_shared<Directory>(fs, path, request.In<uint32_t>(0)));
            return 0;
        case 10: // Commit
            return 0;
        case 11: // GetFreeSpaceSize(path) -> u64
            response.Out(uint64_t{0x400000});
            return 0;
        case 12: // GetTotalSpaceSize(path) -> u64
            response.Out(uint64_t{0x800000});
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<MemoryFileSystem> fs_;
};

// The application's RomFS: an image on the host, read where the title asks.
class RomStorage final : public Interface {
public:
    explicit RomStorage(std::shared_ptr<std::ifstream> file) : file_(std::move(file)) {}
    const char* Name() const override { return "fs IStorage (RomFS)"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // Read(offset, size) -> B
            const auto offset = request.In<int64_t>(0), size = request.In<int64_t>(8);
            if (offset < 0 || size < 0)
                return kOutOfRange;
            std::vector<std::byte> bytes(static_cast<size_t>(size));
            file_->clear();
            file_->seekg(offset);
            if (!file_->read(reinterpret_cast<char*>(bytes.data()), size) || !request.OutBuffer(bytes))
                return kOutOfRange;
            return 0;
        }
        case 4: // GetSize -> s64
            file_->clear();
            file_->seekg(0, std::ios::end);
            response.Out(static_cast<int64_t>(file_->tellg()));
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<std::ifstream> file_;
};

// Saves, shared by every fsp-srv session of the host: system saves by id,
// the application's by their whole attribute.
struct SaveStore {
    std::map<uint64_t, std::shared_ptr<MemoryFileSystem>> saves;
    std::map<std::array<std::byte, 0x40>, std::shared_ptr<MemoryFileSystem>> application_saves;
};

// spl: the security processor's general service, and spl:es, es's, which
// adds its own crypto commands. GetConfig answers as a retail Icosa (the
// original model) does, and IsDevelopment says no; nothing else is served
// yet.
class SecurityProcessor final : public Interface {
public:
    explicit SecurityProcessor(const char* name) : name_(name) {}
    const char* Name() const override { return name_; }
    hk::Result Handle(const Request& request, Response& response) override {
        if (request.command == 11) { // IsDevelopment -> bool
            response.Out(uint8_t{0});
            return 0;
        }
        if (request.command == 2) { // GenerateAesKek(16 bytes source, u32 generation, u32 option) -> access key
            // Access keys are opaque: only spl reads them back. The host has
            // no console keys, and nothing decrypts content through es (the
            // host's fs reads NCAs with the host's own keys), so the source
            // stands for its kek.
            std::array<std::byte, 16> key;
            std::memcpy(key.data(), request.raw.data(), std::min<size_t>(16, request.raw.size()));
            response.Out(key);
            return 0;
        }
        if (request.command == 17) // ImportEsKey(X key, access key, key source): the device's eticket key
            return 0; // kept by no one: the host has no personalized tickets to unwrap
        if (request.command != 0) // GetConfig(u32 item) -> u64
            return kUnknown;
        const uint32_t item = request.In<uint32_t>(0);
        switch (item) {
        case 1:  // DisableProgramVerification
        case 5:  // HardwareType: Icosa
        case 7:  // IsRecoveryBoot
        case 11: // IsDevelopmentFunctionEnabled
        case 13: // IsChargerHiZModeEnabled
        case 14: // RetailInteractiveDisplayState: not a kiosk unit
            response.Out(uint64_t{0});
            return 0;
        case 6: // HardwareState: production
            response.Out(uint64_t{1});
            return 0;
        case 8: // DeviceId: one fixed id until the host keeps an identity of its own
            response.Out(uint64_t{0x0000484F53543031}); // "HOST01"
            return 0;
        default:
            std::fprintf(stderr, "spl: config item %u not known\n", item);
            return kSplInvalidArgument;
        }
    }

private:
    const char* name_;
};

// csrng: random bytes (GenerateRandomBytes, 0), from the host's own source.
class RandomGenerator final : public Interface {
public:
    const char* Name() const override { return "csrng"; }
    hk::Result Handle(const Request& request, Response&) override {
        if (request.command != 0 || request.receives.empty())
            return kUnknown;
        std::vector<std::byte> bytes(request.receives[0].size);
        for (size_t i = 0; i < bytes.size(); i += 4) {
            const uint32_t word = device_();
            std::memcpy(bytes.data() + i, &word, std::min<size_t>(4, bytes.size() - i));
        }
        return request.OutBuffer(bytes) ? 0 : kUnknown;
    }

private:
    std::random_device device_;
};

// fsp-srv: IFileSystemProxy. Commands are added as modules are seen to use them.
class FileSystemProxy final : public Interface {
public:
    FileSystemProxy(std::shared_ptr<SaveStore> store, std::shared_ptr<std::ifstream> romfs, std::string system_data,
                    std::string calibration, bool trace)
        : store_(std::move(store)), romfs_(std::move(romfs)), system_data_(std::move(system_data)),
          calibration_(std::move(calibration)), trace_(trace) {}
    const char* Name() const override { return "fsp-srv"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 1: // SetCurrentProcess(pid)
        case 1003: // DisableAutoSaveDataCreation
        case 1004: // SetGlobalAccessLogMode(mode)
        case 1006: // OutputAccessLogToSdCard(A)
        case 620:  // SetSdCardEncryptionSeed(16 bytes): no SD card to encrypt
        case 630:  // SetSdCardAccessibility(bool)
            return 0;
        case 631: // IsSdCardAccessible -> bool: no SD card
            response.Out(uint8_t{0});
            return 0;
        case 1005: // GetGlobalAccessLogMode -> u32: no access log
            response.Out(uint32_t{0});
            return 0;
        case 1011: // GetProgramIndexForAccessLog -> u32 index, u32 count
            response.Out(std::array<uint32_t, 2>{0, 1});
            return 0;
        case 51: { // OpenSaveDataFileSystem(space, attribute) -> IFileSystem
            // A title's own saves start empty and are made when first opened,
            // as am's EnsureSaveData would have made them.
            std::array<std::byte, 0x40> attribute;
            std::memcpy(attribute.data(), request.raw.data() + 8, std::min<size_t>(0x40, request.raw.size() - 8));
            auto& save = store_->application_saves[attribute];
            if (!save)
                save = std::make_shared<MemoryFileSystem>();
            Trace("opened application", request.In<uint64_t>(8));
            response.objects.push_back(std::make_shared<FileSystem>(save));
            return 0;
        }
        case 200: // OpenDataStorageByCurrentProcess -> IStorage
            if (!romfs_)
                return kTargetNotFound;
            response.objects.push_back(std::make_shared<RomStorage>(romfs_));
            return 0;
        case 12: { // OpenBisStorage(u32 partition) -> IStorage
            const uint32_t partition = request.In<uint32_t>(0);
            auto file = std::make_shared<std::ifstream>(calibration_, std::ios::binary);
            if (partition != 27 || calibration_.empty() || !*file) { // 27: CalibrationBinary
                std::fprintf(stderr, "fsp-srv: no BIS partition %u\n", partition);
                return kTargetNotFound;
            }
            response.objects.push_back(std::make_shared<RomStorage>(std::move(file)));
            return 0;
        }
        case 202: { // OpenDataStorageByDataId(u8 storage id, u64 data id) -> IStorage
            const uint64_t id = request.In<uint64_t>(8);
            char name[32];
            std::snprintf(name, sizeof name, "%016llx.romfs", static_cast<unsigned long long>(id));
            auto file = std::make_shared<std::ifstream>(system_data_ + "/" + name, std::ios::binary);
            if (system_data_.empty() || !*file) {
                std::fprintf(stderr, "fsp-srv: no system data %016llx%c", static_cast<unsigned long long>(id), 10);
                return kTargetNotFound;
            }
            Trace("opened system data", id, "archive");
            response.objects.push_back(std::make_shared<RomStorage>(std::move(file)));
            return 0;
        }
        case 21:   // DeleteSaveDataFileSystem(u64 save data id)
        case 25: { // DeleteSaveDataFileSystemBySaveDataSpaceId(u8 space, u64 save data id)
            const uint64_t id = request.In<uint64_t>(request.command == 25 ? 8 : 0);
            Trace("deleted", id);
            return store_->saves.erase(id) ? 0 : kTargetNotFound;
        }
        case 22: { // CreateSaveDataFileSystem(attribute, creation info, meta info)
            std::array<std::byte, 0x40> attribute;
            std::memcpy(attribute.data(), request.raw.data(), std::min<size_t>(0x40, request.raw.size()));
            auto& save = store_->application_saves[attribute];
            if (save)
                return kPathAlreadyExists;
            save = std::make_shared<MemoryFileSystem>();
            save->size = request.In<int64_t>(0x40); // creation info: size, journal size
            save->journal_size = request.In<int64_t>(0x48);
            Trace("created application", request.In<uint64_t>(0));
            return 0;
        }
        case 23: { // CreateSaveDataFileSystemBySystemSaveDataId(attribute, creation info)
            const uint64_t id = request.In<uint64_t>(0x18);
            if (store_->saves.contains(id))
                return kPathAlreadyExists;
            auto save = std::make_shared<MemoryFileSystem>();
            save->size = request.In<int64_t>(0x40); // creation info: size, journal size
            save->journal_size = request.In<int64_t>(0x48);
            store_->saves[id] = save;
            Trace("created", id);
            return 0;
        }
        case 37: { // CreateSaveDataFileSystemWithCreationInfo2(A creation info 2)
            // A version, the attribute at 8 (its system save id at 0x20, type
            // at 0x28), then size, journal size, block size and owner id from
            // 0x48. Only system saves are made this way so far.
            const std::vector<std::byte> info = request.InBuffer();
            if (info.size() < 0x68)
                return kFsInvalidArgument;
            const auto at = [&]<class T>(size_t offset, T value) {
                std::memcpy(&value, info.data() + offset, sizeof value);
                return value;
            };
            if (at(0x28, uint8_t{}) != 0)
                return kUnknown;
            const uint64_t id = at(0x20, uint64_t{});
            if (store_->saves.contains(id))
                return kPathAlreadyExists;
            auto save = std::make_shared<MemoryFileSystem>();
            save->size = at(0x48, int64_t{});
            save->journal_size = at(0x50, int64_t{});
            store_->saves[id] = save;
            Trace("created", id);
            return 0;
        }
        case 52: { // OpenSaveDataFileSystemBySystemSaveDataId(space, attribute) -> IFileSystem
            const uint64_t id = request.In<uint64_t>(8 + 0x18);
            auto it = store_->saves.find(id);
            Trace("opened", id);
            if (it == store_->saves.end())
                return kTargetNotFound;
            response.objects.push_back(std::make_shared<FileSystem>(it->second));
            return 0;
        }
        case 67: { // FindSaveDataWithFilter(u8 space, SaveDataFilter) -> s64 count, B SaveDataInfo[]
            // The filter: flags for program id, type, user, system save id
            // and index at +8, then a SaveDataAttribute at +0x10. Only system
            // saves are held, so a filter by program or user finds none.
            const auto by = [&](size_t flag) { return request.In<uint8_t>(8 + flag) != 0; };
            const uint64_t id = request.In<uint64_t>(0x10 + 0x18);
            const uint8_t type = request.In<uint8_t>(0x10 + 0x20);
            std::vector<std::byte> infos;
            int64_t count = 0;
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x60;
            for (const auto& [save_id, save] : store_->saves) {
                if (by(0) || by(2) || (by(1) && type != 0) || (by(3) && save_id != id) || by(4))
                    continue;
                if (static_cast<size_t>(count) == capacity)
                    break;
                // SaveDataInfo: save data id, space, type, user id at 0x10,
                // system save id at 0x20, program id, size at 0x30.
                std::array<std::byte, 0x60> info{};
                std::memcpy(&info[0x00], &save_id, 8);
                std::memcpy(&info[0x20], &save_id, 8);
                std::memcpy(&info[0x30], &save->size, 8);
                infos.insert(infos.end(), info.begin(), info.end());
                ++count;
            }
            if (!infos.empty())
                request.OutBuffer(infos);
            response.Out(count);
            return 0;
        }
        case 59:   // WriteSaveDataFileSystemExtraData(u8 space, u64 save data id, A extra data)
        case 61: { // WriteSaveDataFileSystemExtraDataWithMask(u8 space, u64 save data id, A extra data, A mask)
            // The extra data reads back from the save's sizes; the rest is not kept.
            const uint64_t id = request.In<uint64_t>(8);
            Trace("wrote extra data of", id);
            return store_->saves.contains(id) ? 0 : kTargetNotFound;
        }
        case 57:   // ReadSaveDataFileSystemExtraDataBySaveDataSpaceId(u8 space, u64 save data id) -> B
        case 58: { // ReadSaveDataFileSystemExtraData(save data id) -> B
            const uint64_t id = request.In<uint64_t>(request.command == 57 ? 8 : 0);
            Trace("extra data of", id);
            if (!store_->saves.contains(id))
                return kTargetNotFound;
            const auto& save = *store_->saves[id];
            std::vector<std::byte> extra(0x200);
            std::memcpy(extra.data() + 0x18, &id, sizeof id); // the attribute's system save id
            std::memcpy(extra.data() + 0x58, &save.size, sizeof save.size);
            std::memcpy(extra.data() + 0x60, &save.journal_size, sizeof save.journal_size);
            request.OutBuffer(extra);
            return 0;
        }
        case 400: // OpenDeviceOperator -> IDeviceOperator: no SD card, no game card
            response.objects.push_back(std::make_shared<Quiet>("fs IDeviceOperator", std::vector<uint32_t>{}, trace_));
            return 0;
        case 500: // OpenSdCardDetectionEventNotifier -> IEventNotifier
        case 501: // OpenGameCardDetectionEventNotifier
        case 502: // the detection notifiers newer firmware adds
        case 503:
        case 510: // OpenSystemDataUpdateEventNotifier
            // GetEventHandle (0) gives an event that never fires: nothing is
            // inserted or updated.
            response.objects.push_back(std::make_shared<Quiet>("fs IEventNotifier", std::vector<uint32_t>{0}, trace_));
            return 0;
        case 32: { // ExtendSaveDataFileSystem(space, save data id, size, journal size)
            const uint64_t id = request.In<uint64_t>(8);
            Trace("extended", id);
            auto it = store_->saves.find(id);
            if (it == store_->saves.end())
                return kTargetNotFound;
            it->second->size = request.In<int64_t>(16);
            it->second->journal_size = request.In<int64_t>(24);
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    void Trace(const char* what, uint64_t id, const char* kind = "save") const {
        if (trace_)
            std::fprintf(stderr, "fsp-srv: %s %s %016llx\n", what, kind, static_cast<unsigned long long>(id));
    }
    std::shared_ptr<SaveStore> store_;
    std::shared_ptr<std::ifstream> romfs_;
    std::string system_data_, calibration_;
    bool trace_;
};

} // namespace

void AddStubs(NativeHost& host, const StubOptions& options) {
    host.Add("lm", 42, [] { return std::make_shared<LogService>(); });
    std::shared_ptr<std::ifstream> romfs;
    if (!options.romfs.empty()) {
        romfs = std::make_shared<std::ifstream>(options.romfs, std::ios::binary);
        if (!*romfs) {
            std::fprintf(stderr, "fsp-srv: could not open %s\n", options.romfs.c_str());
            romfs.reset();
        }
    }
    host.Add("fsp-srv", 32, [store = std::make_shared<SaveStore>(), romfs, system_data = options.system_data,
                             calibration = options.calibration, trace = options.trace] {
        return std::make_shared<FileSystemProxy>(store, romfs, system_data, calibration, trace);
    });
    host.Add("set:sys", 32, [] { return std::make_shared<SystemSettings>(); });
    if (!options.processes.empty())
        host.Add("pm:info", 16, [processes = options.processes] { return std::make_shared<ProcessInformation>(processes); });
    host.Add("pgl", 8, [launch = options.launch] { return std::make_shared<ProgramLauncher>(launch); });
    for (const char* name : {"spl:", "spl:es"})
        host.Add(name, 8, [name] { return std::make_shared<SecurityProcessor>(name); });
    host.Add("ssl:s", 8, [] { return std::make_shared<SslService>(); });
    host.Add("psc:m", 16, [] { return std::make_shared<PowerService>(); });
    host.Add("npns:s", 8, [trace = options.trace] { return std::make_shared<NotificationSystem>(trace); });
    // pdm:ntfy: play events, which nothing records yet.
    host.Add("pdm:ntfy", 8, [trace = options.trace] { return std::make_shared<Quiet>("pdm:ntfy", std::vector<uint32_t>{}, trace); });
    // nim: network installs, of which there are none without a network.
    host.Add("nim", 8, [trace = options.trace] { return std::make_shared<Quiet>("nim", std::vector<uint32_t>{}, trace); });
    host.Add("csrng", 8, [] { return std::make_shared<RandomGenerator>(); });
    // bcat: background content delivery, of which there is none without a network.
    for (const char* name : {"bcat:u", "bcat:s"})
        host.Add(name, 8, [name, trace = options.trace] {
            return std::make_shared<Bcat>(name, trace);
        });
    // hid:sys: the system side of input, which only ns asks so far.
    host.Add("hid:sys", 8, [trace = options.trace] { return std::make_shared<Quiet>("hid:sys", std::vector<uint32_t>{713}, trace); });
    // caps:c: the album's control, for an album that stays empty.
    host.Add("caps:c", 8, [trace = options.trace] { return std::make_shared<Quiet>("caps:c", std::vector<uint32_t>{}, trace); });
    host.Add("srepo:u", 8, [trace = options.trace] { return std::make_shared<SystemReports>(trace); });
    host.Add("bgtc:t", 8, [trace = options.trace] { return std::make_shared<BackgroundTaskFactory>(trace); });
    for (const char* name : {"fatal:u", "acc:e:u1", "bsdcfg", "dauth:0", "nsd:u", "pdm:qry", "set",
                             "set:cal", "sfdnsres", "spl:mig", "ectx:w", "es", "caps:dc", "avm", "ndrm:lu"})
        host.Add(name, 8, [name] { return std::make_shared<Placeholder>(name); });
    for (const char* name : {"time:u", "time:su"}) // the same IStaticService
        host.Add(name, 32, [] { return std::make_shared<TimeService>(); });
    host.Add("nifm:s", 16, [] { return std::make_shared<NetworkStatic>(); });
    host.Add("bsd:s", 32, [] { return std::make_shared<Sockets>(); });
    host.Add("arp:r", 16, [application = options.application] { return std::make_shared<ApplicationReader>(application); });
    host.Add("arp:w", 8, [trace = options.trace] { return std::make_shared<ApplicationWriter>(trace); });
    host.Add("ovln:snd", 8, [] { return std::make_shared<OverlaySenderService>(); });
    host.Add("pm:bm", 6, [mode = options.boot_mode] { return std::make_shared<BootMode>(mode); });
}

} // namespace services
