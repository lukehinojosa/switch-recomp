// A native service manager serving "sm:".
//
// Services become kernel named ports: RegisterService publishes one and moves
// its server port to the caller, GetServiceHandle connects to one and moves
// the client session. Ports registered this way are therefore announced across
// kernel links like any named port.
#pragma once

#include "hk/kernel.h"

#include <cstdint>
#include <memory>

namespace services {

class ServiceManager {
public:
    // Creates sm's process in kernel and starts serving on a host thread,
    // which runs until the host process exits.
    explicit ServiceManager(hk::Kernel& kernel, bool trace = false);
    ~ServiceManager();
    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;

    struct State;

private:
    std::unique_ptr<State> state_;
};

} // namespace services
