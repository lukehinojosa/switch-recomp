#include "stubs.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);
const hk::Result kTargetNotFound = MakeResult(2, 1002); // fs
const hk::Result kArpNotRegistered = MakeResult(157, 102);
const hk::Result kSettingsItemNotFound = MakeResult(105, 11);

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
        case 2: // GetApplicationControlProperty(pid) -> B
        case 3: // GetApplicationControlPropertyWithApplicationId(application id) -> B
            if (!Matches(request))
                return kArpNotRegistered;
            return request.OutBuffer(application_->control) ? 0 : kUnknown;
        case 6: // GetApplicationInstanceId(pid) -> instance id (libnx's numbering; pctl sends a PID)
            if (!application_ || request.In<uint64_t>(0) != application_->process_id)
                return kArpNotRegistered;
            response.Out(uint64_t{1}); // the first application launched since boot
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    bool Matches(const Request& request) const {
        if (!application_)
            return false;
        const auto key = request.In<uint64_t>(0);
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

// nifm IGeneralService: no network interface is up.
class NetworkGeneral final : public Interface {
public:
    const char* Name() const override { return "nifm IGeneralService"; }
    hk::Result Handle(const Request&, Response&) override { return kUnknown; }
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
// correction at 0xc8. A snapshot is enough: the contexts are offsets that stay
// valid as the guest's tick counter advances.
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

// A service that only matters with a network, which is down: commands that
// return an event get one that never fires, every other command succeeds
// with zeroed output. Each command is logged when tracing.
class Quiet final : public Interface {
public:
    Quiet(std::string name, std::vector<uint32_t> event_commands, bool trace)
        : name_(std::move(name)), events_(std::move(event_commands)), trace_(trace) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request& request, Response& response) override {
        if (trace_)
            std::fprintf(stderr, "%s: command %u accepted%c", name_.c_str(), request.command, 10);
        if (std::find(events_.begin(), events_.end(), request.command) != events_.end())
            response.copy.push_back(request.create_event());
        else
            response.Out(std::array<uint64_t, 2>{});
        return 0;
    }

private:
    std::string name_;
    std::vector<uint32_t> events_;
    bool trace_;
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
std::string PathOf(const Request& request) {
    const auto bytes = request.InBuffer(0);
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

// System saves, shared by every fsp-srv session of the host.
struct SaveStore {
    std::map<uint64_t, std::shared_ptr<MemoryFileSystem>> saves;
};

// fsp-srv: IFileSystemProxy. Commands are added as modules are seen to use them.
class FileSystemProxy final : public Interface {
public:
    FileSystemProxy(std::shared_ptr<SaveStore> store, bool trace) : store_(std::move(store)), trace_(trace) {}
    const char* Name() const override { return "fsp-srv"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 1: // SetCurrentProcess(pid)
            return 0;
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
        case 52: { // OpenSaveDataFileSystemBySystemSaveDataId(space, attribute) -> IFileSystem
            const uint64_t id = request.In<uint64_t>(8 + 0x18);
            auto it = store_->saves.find(id);
            Trace("opened", id);
            if (it == store_->saves.end())
                return kTargetNotFound;
            response.objects.push_back(std::make_shared<FileSystem>(it->second));
            return 0;
        }
        case 58: { // ReadSaveDataFileSystemExtraData(save data id) -> B
            const uint64_t id = request.In<uint64_t>(0);
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
    void Trace(const char* what, uint64_t id) const {
        if (trace_)
            std::fprintf(stderr, "fsp-srv: %s save %016llx\n", what, static_cast<unsigned long long>(id));
    }
    std::shared_ptr<SaveStore> store_;
    bool trace_;
};

} // namespace

void AddStubs(NativeHost& host, const StubOptions& options) {
    host.Add("lm", 42, [] { return std::make_shared<LogService>(); });
    host.Add("fsp-srv", 32, [store = std::make_shared<SaveStore>(), trace = options.trace] {
        return std::make_shared<FileSystemProxy>(store, trace);
    });
    host.Add("set:sys", 32, [] { return std::make_shared<SystemSettings>(); });
    host.Add("ssl:s", 8, [] { return std::make_shared<SslService>(); });
    host.Add("psc:m", 16, [] { return std::make_shared<PowerService>(); });
    // npns:s: GetReceiveEvent, GetStateChangeEvent.
    host.Add("npns:s", 8, [trace = options.trace] { return std::make_shared<Quiet>("npns:s", std::vector<uint32_t>{5, 7}, trace); });
    host.Add("bgtc:t", 8, [trace = options.trace] { return std::make_shared<BackgroundTaskFactory>(trace); });
    for (const char* name : {"fatal:u", "acc:e:u1", "bsdcfg", "dauth:0", "nsd:u", "pdm:qry", "set",
                             "set:cal", "sfdnsres", "srepo:u"})
        host.Add(name, 8, [name] { return std::make_shared<Placeholder>(name); });
    host.Add("time:u", 32, [] { return std::make_shared<TimeService>(); });
    host.Add("nifm:s", 16, [] { return std::make_shared<NetworkStatic>(); });
    host.Add("bsd:s", 32, [] { return std::make_shared<Sockets>(); });
    host.Add("arp:r", 16, [application = options.application] { return std::make_shared<ApplicationReader>(application); });
    host.Add("ovln:snd", 8, [] { return std::make_shared<OverlaySenderService>(); });
    host.Add("pm:bm", 6, [mode = options.boot_mode] { return std::make_shared<BootMode>(mode); });
}

} // namespace services
