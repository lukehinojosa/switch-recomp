// vi: the display service, native. Until the host window exists (plan.md,
// phase 2) it is a display that shows nothing: one 1920x1080 display with a
// vsync at 60 Hz, layers, and the buffer queue (Android's
// IGraphicBufferProducer over binder) a title presents through, which takes
// every buffer back at once.
#pragma once

#include "native.h"

namespace services {

void AddDisplay(NativeHost& host, bool trace);

} // namespace services
