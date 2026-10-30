#include "application.h"

#include "nvdrv.h"
#include "vi.h"

#include <array>
#include <cstring>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <tuple>
#include <mutex>
#include <string>
#include <utility>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);
const hk::Result kNoMessage = MakeResult(128, 3);     // am: the message queue is empty
const hk::Result kNoData = MakeResult(128, 2);        // am: nothing in the channel
const hk::Result kOutOfRange = MakeResult(128, 503);  // am: storage access past its end

using Handler = std::function<hk::Result(const Request&, Response&)>;

// An interface given as a table of commands.
class Commands final : public Interface {
public:
    Commands(std::string name, std::map<uint32_t, Handler> commands)
        : name_(std::move(name)), commands_(std::move(commands)) {}
    const char* Name() const override { return name_.c_str(); }
    hk::Result Handle(const Request& request, Response& response) override {
        auto it = commands_.find(request.command);
        return it == commands_.end() ? kUnknown : it->second(request, response);
    }

private:
    std::string name_;
    std::map<uint32_t, Handler> commands_;
};

std::shared_ptr<Interface> Make(std::string name, std::map<uint32_t, Handler> commands) {
    return std::make_shared<Commands>(std::move(name), std::move(commands));
}

// Handlers for the common shapes: accept and return nothing, return a fixed
// value, return a sub-interface, return an event that is never signalled.
Handler Accept() {
    return [](const Request&, Response&) { return hk::Result{0}; };
}
template <class T>
Handler Value(T value) {
    return [value](const Request&, Response& response) {
        response.Out(value);
        return hk::Result{0};
    };
}
Handler Object(std::function<std::shared_ptr<Interface>()> make) {
    return [make = std::move(make)](const Request&, Response& response) {
        response.objects.push_back(make());
        return hk::Result{0};
    };
}
Handler Event() {
    return [](const Request& request, Response& response) {
        response.copy.push_back(request.create_event());
        return hk::Result{0};
    };
}

// An event the service signals itself, created on first use; every request
// for it copies out the same readable handle.
class OwnEvent {
public:
    uint32_t Readable(const Request& request) {
        if (!readable_)
            std::tie(writable_, readable_) = request.create_event_pair();
        return readable_;
    }
    void Set(const Request& request, bool signaled) {
        Readable(request);
        signaled ? request.signal_event(writable_) : request.clear_event(writable_);
    }

private:
    uint32_t writable_ = 0, readable_ = 0;
};

// "en-US" as settings encodes a language: the text in a little-endian u64.
constexpr uint64_t kLanguageCode = 0x00000053552D6E65ull;

// --- am: the applet manager, as an application sees it through appletOE ---

// What the application is told: the messages it is sent and how it is shown.
// A desktop host is a docked console in focus.
struct AppletState {
    std::mutex mutex;
    std::deque<uint32_t> messages{15}; // FocusStateChanged: the application starts in focus
    OwnEvent message_event;
    uint64_t aruid = 0;
};

std::shared_ptr<Interface> CommonStateGetter(std::shared_ptr<AppletState> state) {
    return Make("am ICommonStateGetter", {
        {0, [state](const Request& request, Response& response) { // GetEventHandle
             std::lock_guard lock(state->mutex);
             response.copy.push_back(state->message_event.Readable(request));
             state->message_event.Set(request, !state->messages.empty());
             return hk::Result{0};
         }},
        {1, [state](const Request& request, Response& response) { // ReceiveMessage -> u32
             std::lock_guard lock(state->mutex);
             if (state->messages.empty())
                 return kNoMessage;
             response.Out(state->messages.front());
             state->messages.pop_front();
             state->message_event.Set(request, !state->messages.empty());
             return hk::Result{0};
         }},
        {5, Value<uint8_t>(1)},          // GetOperationMode: console (docked)
        {6, Value<uint32_t>(1)},         // GetPerformanceMode: boost (docked)
        {8, Value<uint8_t>(0)},          // GetBootMode: normal
        {9, Value<uint8_t>(1)},          // GetCurrentFocusState: in focus
        {10, Accept()},                  // RequestToAcquireSleepLock
        {50, Value<uint8_t>(0)},         // IsVrModeEnabled
        {51, Accept()},                  // SetVrModeEnabled
        {52, Accept()},                  // SetLcdBacklighOffEnabled
        {53, Accept()},                  // BeginVrModeEx
        {54, Accept()},                  // EndVrModeEx
        {55, Value<uint8_t>(0)},         // IsInControllerFirmwareUpdateSection
        {60, Value(std::array<int32_t, 2>{1920, 1080})}, // GetDefaultDisplayResolution
        {61, Event()},                   // GetDefaultDisplayResolutionChangeEvent
        {66, Accept()},                  // SetCpuBoostMode
        {300, Value<uint32_t>(1)},       // GetSettingsPlatformRegion: global
        {900, Accept()},                 // SetRequestExitToLibraryAppletAtExecuteNextProgramEnabled
    });
}

std::shared_ptr<Interface> SelfController(std::shared_ptr<AppletState>) {
    std::map<uint32_t, Handler> commands{
        {9, [](const Request& request, Response& response) { // GetLibraryAppletLaunchableEvent
             auto [writable, readable] = request.create_event_pair();
             request.signal_event(writable); // launching an applet is always possible
             response.copy.push_back(readable);
             return hk::Result{0};
         }},
        {40, Value<uint64_t>(1)},        // CreateManagedDisplayLayer -> layer id
        {69, Value<uint8_t>(0)},         // IsAutoSleepDisabled
        {91, Value<uint64_t>(0)},        // GetAccumulatedSuspendedTickValue
        {92, Event()},                   // GetAccumulatedSuspendedTickChangedEvent
    };
    // Settings the application makes about itself, which a host has no use for:
    // LockExit, UnlockExit, SetScreenShotPermission, the mode-change
    // notifications, SetFocusHandlingMode, SetRestartMessageEnabled,
    // SetOutOfFocusSuspendingEnabled, SetAlbumImageOrientation,
    // SetHandlesRequestToDisplay, SetIdleTimeDetectionExtension,
    // ReportUserIsActive, SetAutoSleepDisabled, and the like.
    for (uint32_t command : {1, 2, 10, 11, 12, 13, 14, 16, 18, 19, 50, 51, 62, 65, 68, 72, 80, 100, 110, 120})
        commands.emplace(command, Accept());
    return Make("am ISelfController", std::move(commands));
}

std::shared_ptr<Interface> WindowController(std::shared_ptr<AppletState> state) {
    return Make("am IWindowController", {
        {1, [state](const Request&, Response& response) { // GetAppletResourceUserId
             response.Out(state->aruid);
             return hk::Result{0};
         }},
        {10, Accept()}, // AcquireForegroundRights
    });
}

std::shared_ptr<Interface> AudioController() {
    return Make("am IAudioController", {
        {0, Accept()},              // SetExpectedMasterVolume
        {1, Value<float>(1.0f)},    // GetMainAppletExpectedMasterVolume
        {2, Value<float>(1.0f)},    // GetLibraryAppletExpectedMasterVolume
        {3, Accept()},              // ChangeMainAppletMasterVolume
        {4, Accept()},              // SetTransparentVolumeRate
    });
}

// IStorage over a block of bytes, and the accessor it opens.
std::shared_ptr<Interface> Storage(std::shared_ptr<std::vector<std::byte>> bytes) {
    auto accessor = [bytes] {
        return Make("am IStorageAccessor", {
            {0, [bytes](const Request&, Response& response) { // GetSize -> s64
                 response.Out(static_cast<int64_t>(bytes->size()));
                 return hk::Result{0};
             }},
            {10, [bytes](const Request& request, Response&) { // Write(s64 offset, A)
                 const auto offset = static_cast<uint64_t>(request.In<int64_t>(0));
                 const auto in = request.InBuffer();
                 if (offset > bytes->size() || in.size() > bytes->size() - offset)
                     return kOutOfRange;
                 std::copy(in.begin(), in.end(), bytes->begin() + static_cast<ptrdiff_t>(offset));
                 return hk::Result{0};
             }},
            {11, [bytes](const Request& request, Response&) { // Read(s64 offset) -> B
                 const auto offset = static_cast<uint64_t>(request.In<int64_t>(0));
                 if (offset > bytes->size())
                     return kOutOfRange;
                 request.OutBuffer(std::span(*bytes).subspan(offset));
                 return hk::Result{0};
             }},
        });
    };
    return Make("am IStorage", {{0, Object(accessor)}}); // Open
}

// The launch parameter account::OpenPreselectedUser reads: the user the
// console picked before starting the application.
std::shared_ptr<std::vector<std::byte>> PreselectedUser() {
    auto bytes = std::make_shared<std::vector<std::byte>>(0x88);
    const uint32_t magic = 0xC79497CA, selected = 1;
    const std::array<uint64_t, 2> uid{0x0000000000000001ull, 0x0000000000000001ull};
    std::memcpy(bytes->data(), &magic, 4);
    std::memcpy(bytes->data() + 4, &selected, 4);
    std::memcpy(bytes->data() + 8, uid.data(), 16);
    return bytes;
}

std::shared_ptr<Interface> ApplicationFunctions() {
    std::map<uint32_t, Handler> commands{
        {1, [](const Request& request, Response& response) { // PopLaunchParameter(kind) -> IStorage
             if (request.In<uint32_t>(0) != 2) // only the preselected user is ever passed
                 return kNoData;
             response.objects.push_back(Storage(PreselectedUser()));
             return hk::Result{0};
         }},
        {20, Value<uint64_t>(0)},              // EnsureSaveData(uid) -> required size: none
        {21, Value<uint64_t>(kLanguageCode)},  // GetDesiredLanguage
        {23, Value(std::array<char, 16>{'1', '.', '0', '.', '0'})}, // GetDisplayVersion
        {25, Value<uint64_t>(0)},              // ExtendSaveData -> required size: none
        {26, Value(std::array<int64_t, 2>{0x4000000, 0x4000000})}, // GetSaveDataSize
        {40, Value<uint8_t>(0)},               // NotifyRunning -> whether to become active
        {50, Value(std::array<uint64_t, 2>{0x0123456789ABCDEFull, 0xFEDCBA9876543210ull})}, // GetPseudoDeviceId
        {110, Value<uint32_t>(0)},             // QueryApplicationPlayStatistics -> count
        {123, Value<int32_t>(-1)},             // GetPreviousProgramIndex: none
        {130, Event()},                        // GetGpuErrorDetectedSystemEvent
        {140, Event()},                        // GetFriendInvitationStorageChannelEvent
        {150, Event()},                        // GetNotificationStorageChannelEvent
    };
    // SetTerminateResult, InitializeGamePlayRecording, SetGamePlayRecordingState,
    // EnableApplicationCrashReport, and the copyright frame buffer commands.
    for (uint32_t command : {22, 66, 67, 90, 100, 101, 102})
        commands.emplace(command, Accept());
    return Make("am IApplicationFunctions", std::move(commands));
}

std::shared_ptr<Interface> ApplicationProxy(std::shared_ptr<AppletState> state) {
    return Make("am IApplicationProxy", {
        {0, Object([state] { return CommonStateGetter(state); })},
        {1, Object([state] { return SelfController(state); })},
        {2, Object([state] { return WindowController(state); })},
        {3, Object(AudioController)},
        {4, Object([] { return Make("am IDisplayController", {}); })},
        {10, Object([] { return Make("am IProcessWindingController", {}); })},
        {11, Object([] { return Make("am ILibraryAppletCreator", {}); })},
        {20, Object(ApplicationFunctions)},
        {1000, Object([] { return Make("am IDebugFunctions", {}); })},
    });
}

std::shared_ptr<Interface> ApplicationProxyService(std::shared_ptr<AppletState> state) {
    return Make("appletOE", {
        {0, [state](const Request& request, Response& response) { // OpenApplicationProxy(pid, process)
             state->aruid = request.pid;
             response.objects.push_back(ApplicationProxy(state));
             return hk::Result{0};
         }},
    });
}

// --- the rest, in the order a title asks for them ---

std::shared_ptr<Interface> PerformanceManager() {
    auto session = [] {
        return Make("apm ISession", {
            {0, Accept()},                   // SetPerformanceConfiguration(mode, config)
            {1, Value<uint32_t>(0x00020003)}, // GetPerformanceConfiguration(mode): docked default
        });
    };
    return Make("apm", {
        {0, Object(session)},  // OpenSession
        {1, Value<uint32_t>(1)}, // GetPerformanceMode: boost (docked)
        {6, Value<uint8_t>(0)},  // IsCpuOverclockEnabled
    });
}

std::shared_ptr<Interface> AddOnContent(uint64_t program_id) {
    auto purchases = [] {
        return Make("aoc IPurchaseEventManager", {
            {0, Accept()}, // SetDefaultDeliveryTarget
            {1, Accept()}, // SetDeliveryTarget
            {2, Event()},  // GetPurchasedEventReadableHandle
            {3, [](const Request&, Response&) { return MakeResult(166, 400); }}, // PopPurchasedProductInfo: none
        });
    };
    // No add-on content is installed.
    return Make("aoc:u", {
        {2, Value<uint32_t>(0)},                    // CountAddOnContent(pid)
        {3, Value<uint32_t>(0)},                    // ListAddOnContent(offset, count, pid) -> count
        {5, Value<uint64_t>(program_id + 0x1000)},  // GetAddOnContentBaseId(pid)
        {7, Accept()},                              // PrepareAddOnContent(index, pid)
        {8, Event()},                               // GetAddOnContentListChangedEvent
        {9, Value<uint32_t>(0)},                    // GetAddOnContentLostErrorCode
        {10, Event()},                              // GetAddOnContentListChangedEventWithProcessId
        {100, Object(purchases)},                   // CreateEcPurchasedEventManager
        {101, Object(purchases)},                   // CreatePermanentEcPurchasedEventManager
    });
}

// pctl with no restrictions set: what a console without parental controls
// answers (the recompiled pctl agrees on these; see tests/pctl_shadow.cpp).
std::shared_ptr<Interface> ParentalControl(const char* name) {
    auto service = [] {
        return Make("pctl IParentalControlService", {
            {1, Accept()},              // Initialize
            {1001, Accept()},           // CheckFreeCommunicationPermission
            {1031, Value<uint8_t>(0)},  // IsRestrictionEnabled
            {1062, Value<uint8_t>(0)},  // GetStereoVisionRestriction
            {1065, Value<uint8_t>(1)},  // IsStereoVisionPermitted
            {1403, Value<uint8_t>(0)},  // IsPairingActive
            {1432, Event()},            // GetSynchronizationEvent
            {1451, Accept()},           // StartPlayTimer
            {1452, Accept()},           // StopPlayTimer
            {1456, Value(std::array<uint64_t, 8>{})}, // GetPlayTimerSettings
            {1457, Event()},            // GetPlayTimerEventToRequestSuspension
            {1473, Event()},            // GetUnlinkedEvent
        });
    };
    return Make(name, {{0, Object(service)}, {1, Object(service)}}); // CreateService, ...WithoutInitialize
}

std::shared_ptr<Interface> Settings() {
    return Make("set", {
        {0, Value<uint64_t>(kLanguageCode)}, // GetLanguageCode
        {1, [](const Request& request, Response& response) { // GetAvailableLanguageCodes -> s32, B
             request.OutBuffer(std::as_bytes(std::span(&kLanguageCode, 1)));
             response.Out(int32_t{1});
             return hk::Result{0};
         }},
        {3, Value<int32_t>(1)},              // GetAvailableLanguageCodeCount
        {4, Value<int32_t>(1)},              // GetRegionCode: USA
        {5, [](const Request& request, Response& response) { // GetAvailableLanguageCodes2 -> s32, B
             request.OutBuffer(std::as_bytes(std::span(&kLanguageCode, 1)));
             response.Out(int32_t{1});
             return hk::Result{0};
         }},
        {6, Value<int32_t>(1)},              // GetAvailableLanguageCodeCount2
    });
}

// hid with no controllers: its shared memory stays zero, which reads as
// nothing connected. Host input replaces it in phase 2.
std::shared_ptr<Interface> Input() {
    auto applet_resource = [] {
        return Make("hid IAppletResource", {
            {0, [](const Request& request, Response& response) { // GetSharedMemoryHandle
                 response.copy.push_back(request.create_shared_memory(std::vector<std::byte>(0x40000)));
                 return hk::Result{0};
             }},
        });
    };
    auto vibration_list = [] { return Make("hid IActiveVibrationDeviceList", {{0, Accept()}}); };
    std::map<uint32_t, Handler> commands{
        {0, Object(applet_resource)},  // CreateAppletResource(aruid)
        {40, Event()},                 // AcquireXpadIdEventHandle
        {101, Value<uint32_t>(0)},     // GetSupportedNpadStyleSet
        {106, Event()},                // AcquireNpadStyleSetUpdateEventHandle(npad, aruid)
        {108, Value<uint64_t>(0)},     // GetPlayerLedPattern
        {121, Value<uint64_t>(1)},     // GetNpadJoyHoldType: horizontal
        {129, Value<uint64_t>(0)},     // GetNpadHandheldActivationMode
        {131, Value<uint8_t>(0)},      // IsUnintendedHomeButtonInputProtectionEnabled
        {200, Value(std::array<uint32_t, 2>{})}, // GetVibrationDeviceInfo: no device
        {203, Object(vibration_list)}, // CreateActiveVibrationDeviceList
        {205, Value<uint8_t>(1)},      // IsVibrationPermitted
        {211, Value<uint8_t>(0)},      // IsVibrationDeviceMounted
        {400, Value<uint8_t>(0)},      // IsUsbFullKeyControllerEnabled
        {1001, Value<uint64_t>(0)},    // GetNpadCommunicationMode
    };
    // Activation and settings, which only shape what the shared memory would
    // report: the debug pad, touch screen, mouse, keyboard, six-axis sensors,
    // the supported styles and ids, npad activation, the joy-con assignment
    // modes, vibration, and the like.
    for (uint32_t command : {1, 11, 21, 31, 32, 66, 67, 69, 70, 79, 100, 102, 103, 104, 107, 109, 120, 122, 123,
                             124, 125, 126, 127, 128, 130, 132, 133, 134, 135, 136, 201, 204, 206, 209, 210, 300,
                             301, 302, 401, 1000, 1002, 2000})
        commands.emplace(command, Accept());
    return Make("hid", std::move(commands));
}

} // namespace

void AddApplicationServices(NativeHost& host, const ApplicationOptions& options) {
    host.Add("hid", 8, [] { return Input(); });
    auto applet = std::make_shared<AppletState>();
    host.Add("appletOE", 4, [applet] { return ApplicationProxyService(applet); });
    host.Add("apm", 8, [] { return PerformanceManager(); });
    host.Add("aoc:u", 8, [id = options.program_id] { return AddOnContent(id); });
    for (const char* name : {"pctl", "pctl:s", "pctl:r", "pctl:a"})
        host.Add(name, 8, [name] { return ParentalControl(name); });
    host.Add("set", 8, [] { return Settings(); });
    AddNvdrv(host, options.trace);
    AddDisplay(host, options.trace);
}

} // namespace services
