// A client that checks a module host is serving pctl: it connects to "pctl",
// opens an IParentalControlService with CreateService and asks
// IsRestrictionEnabled, prints what came back and ends the host process.
// Exit code 0 means both calls reached the module and got CMIF replies.
#pragma once

#include "hk/kernel.h"

#include <string>

namespace services {

void StartPctlProbe(hk::Kernel& kernel);

// Launches an application the way am does: gets ns's
// IApplicationManagerInterface from ns:am2, gets the application's launch
// info and asks ns to LaunchApplication, which acquires its rights from es
// and calls pgl LaunchProgram, then acquires the launch info. First it
// pushes ns an application record for each application installed in the
// content index (tools/nca.py --content-index), as an installer does. Prints
// the results; the host's pgl starts the title.
void StartLaunch(hk::Kernel& kernel, uint64_t program_id, std::string content);

} // namespace services
