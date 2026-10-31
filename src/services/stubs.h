// Stub services for running a recompiled module on its own. Each answers
// only the commands a module has been seen to call, with the value a
// stand-alone console would give; anything else is reported as unknown.
#pragma once

#include "native.h"

#include <functional>
#include <map>
#include <optional>
#include <string>

namespace services {

// An application process as arp registers it at launch.
struct Application {
    uint64_t process_id = 0;
    uint64_t program_id = 0;
    uint32_t version = 0;
    std::vector<std::byte> control; // its control.nacp
};

struct StubOptions {
    // pm:bm GetBootMode: 0 normal, 1 maintenance.
    uint32_t boot_mode = 0;
    // What arp:r reports as running; none means no process is an application.
    std::optional<Application> application;
    // The running title's RomFS image, which fsp-srv serves as its data
    // storage; none for a module.
    std::string romfs;
    // A folder of the firmware's system data archives as RomFS images named
    // <data id>.romfs (tools/nca.py --system-data), which fsp-srv serves.
    std::string system_data;
    // The console's calibration data (PRODINFO, a CAL0 image), which fsp-srv
    // serves as BIS partition 27 (tools/calibration.py writes one).
    std::string calibration;
    // Every process the host runs, by process id: its program id. When set,
    // this host serves pm:info for all of them (the root host does; the
    // sysmodules it starts reach that one).
    std::map<uint64_t, uint64_t> processes;
    // pgl LaunchProgram: starts the program and gives its process id, or
    // none if the host cannot run it. Unset, pgl launches nothing.
    std::function<std::optional<uint64_t>(uint64_t program_id)> launch;
    bool trace = false;
};

// Adds every stub to host.
void AddStubs(NativeHost& host, const StubOptions& options);

} // namespace services
