// A client that checks a module host is serving pctl: it connects to "pctl",
// opens an IParentalControlService with CreateService and asks
// IsRestrictionEnabled, prints what came back and ends the host process.
// Exit code 0 means both calls reached the module and got CMIF replies.
#pragma once

#include "hk/kernel.h"

namespace services {

void StartPctlProbe(hk::Kernel& kernel);

} // namespace services
