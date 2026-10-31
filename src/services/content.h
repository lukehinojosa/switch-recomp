// Content management, native over the host's files: ncm (content storages
// and content meta databases) and lr (location resolution), from the index
// tools/nca.py --content-index writes. The firmware's contents are
// BuiltInSystem's and the user's installed titles BuiltInUser's; the game
// card and the SD card are empty.
#pragma once

#include "native.h"

#include <string>

namespace services {

// Adds ncm and lr over the index in folder (none: every storage is empty).
void AddContentServices(NativeHost& host, const std::string& folder, bool trace);

} // namespace services
