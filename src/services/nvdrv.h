// nvdrv: the GPU driver's service, native. It keeps the bookkeeping a title's
// NVN driver relies on (nvmap handles, GPU address space mappings, channels,
// syncpoints) and records what the title submits; no GPU runs the commands
// yet, so every submission completes at once. Phase 3 replaces this path
// with NVN on Vulkan (plan.md); until then it is the reference path, where
// the game's own NVN reaches the hardware interface.
#pragma once

#include "native.h"

namespace services {

void AddNvdrv(NativeHost& host, bool trace);

} // namespace services
