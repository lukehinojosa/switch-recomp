// A native CMIF service in its own host process, for client_test:
// cmif_host --link <read> <write>. Port "test" answers
//   0 Echo(raw) -> raw            1 OpenSub() -> the same interface, moved
//   2 WhoAmI(pid) -> pid          3 Crash(): the host process ends at once
// Runs until its parent kills it.
#include "hk/link.h"
#include "services/native.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {

class Test final : public services::Interface {
public:
    const char* Name() const override { return "test"; }
    hk::Result Handle(const services::Request& request, services::Response& response) override {
        switch (request.command) {
        case 0:
            response.raw = request.raw;
            return 0;
        case 1:
            response.objects.push_back(std::make_shared<Test>());
            return 0;
        case 2:
            response.Out(request.pid);
            return 0;
        case 3:
            std::_Exit(9);
        default:
            return services::MakeResult(10, 221);
        }
    }
};

} // namespace

int main(int argc, char** argv) {
    if (argc != 4 || std::strcmp(argv[1], "--link") != 0) {
        std::fprintf(stderr, "usage: cmif_host --link <read> <write>\n");
        return 2;
    }
    hk::Kernel kernel;
    services::NativeHost host(kernel, false);
    host.Add("test", 4, [] { return std::make_shared<Test>(); });
    host.Start();
    kernel.AttachLink(hk::OpenPipeStream(std::strtoull(argv[2], nullptr, 10), std::strtoull(argv[3], nullptr, 10)),
                      false);
    for (;;)
        std::this_thread::sleep_for(std::chrono::hours(1));
}
