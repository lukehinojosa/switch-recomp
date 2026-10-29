#include "echo_server.h"

namespace echo {

hk::Result RunServer(hk_thread* thread, TestMemory& memory, uint64_t tls, uint64_t scratch) {
    using namespace hk::result;
    const uint64_t name = scratch, handle_list = scratch + 0x10;
    memory.WriteString(name, "echo");
    uint32_t port;
    if (const auto r = svc::ManageNamedPort(thread, name, MaxSessions, port))
        return r;

    std::vector<uint32_t> handles{port}; // waited on
    std::vector<uint32_t> held;          // kept but not served
    uint32_t reply_target = 0;
    for (;;) {
        memory.WriteWords(handle_list, handles);
        uint32_t index;
        const auto r = svc::ReplyAndReceive(thread, handle_list, static_cast<uint32_t>(handles.size()), reply_target,
                                            -1, index);
        reply_target = 0;
        if (r == SessionClosed && index > 0) {
            svc::CloseHandle(thread, handles[index]);
            handles.erase(handles.begin() + index);
            continue;
        }
        if (r)
            return r;
        if (index == 0) {
            uint32_t session;
            if (const auto e = svc::AcceptSession(thread, port, session))
                return e;
            handles.push_back(session);
            continue;
        }

        const Message request = ReadMessage(memory, tls);
        Message reply;
        reply.type = 0;
        reply.data = {0};
        switch (request.data.empty() ? 0 : request.data[0]) {
        case Echo:
            reply.data = request.data;
            // Keep handles sent with an echo, so tests can watch them arrive.
            held.insert(held.end(), request.copy.begin(), request.copy.end());
            held.insert(held.end(), request.move.begin(), request.move.end());
            break;
        case WhoAmI:
            reply.data = {static_cast<uint32_t>(request.pid), static_cast<uint32_t>(request.pid >> 32)};
            break;
        case OpenSub: {
            uint32_t server, client;
            if (const auto e = svc::CreateSession(thread, server, client))
                return e;
            handles.push_back(server);
            reply.move = {client};
            break;
        }
        case Adopt:
            handles.insert(handles.end(), request.move.begin(), request.move.end());
            break;
        case Stats:
            reply.data = {static_cast<uint32_t>(handles.size() + held.size())};
            break;
        case Quit: {
            WriteMessage(memory, tls, reply);
            // Reply with nothing to wait on: the kernel replies, then times out.
            if (const auto e = svc::ReplyAndReceive(thread, handle_list, 0, handles[index], 0, index); e != TimedOut)
                return e;
            for (const uint32_t handle : handles)
                svc::CloseHandle(thread, handle);
            for (const uint32_t handle : held)
                svc::CloseHandle(thread, handle);
            return Success;
        }
        default:
            reply.data = {0xffffffff};
            break;
        }
        WriteMessage(memory, tls, reply);
        reply_target = handles[index];
    }
}

} // namespace echo
