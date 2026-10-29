#include "echo_server.h"

namespace echo {

hk::Result RunServer(hk_thread* thread, FlatMemory& memory, uint64_t tls, uint64_t scratch) {
    using namespace hk::result;
    const uint64_t name = scratch, handle_list = scratch + 0x10;
    memory.WriteString(name, "echo");
    uint32_t port;
    if (const auto r = svc::ManageNamedPort(thread, name, MaxSessions, port))
        return r;

    std::vector<uint32_t> handles{port}; // waited on
    std::vector<uint32_t> held;          // kept but not served
    const uint64_t receive_buffer = tls + ReceiveOffset, reply_static = tls + ReceiveOffset + ReceiveSize;
    // The receive list rides in every message the server leaves in its buffer,
    // after the data, where replies never reach.
    auto with_receive_list = [&](Message& message) {
        message.receive_list = {{receive_buffer, ReceiveSize}};
        message.receive_list_word = 0x38;
    };
    uint32_t reply_target = 0;
    for (;;) {
        if (!reply_target) {
            Message idle;
            idle.type = 0;
            with_receive_list(idle);
            WriteMessage(memory, tls, idle);
        }
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
        case Buffers: {
            if (request.statics.size() != 1 || request.sends.size() != 1 || request.receives.size() != 1 ||
                request.exchanges.size() != 1) {
                reply.data = {0xffffffff};
                break;
            }
            const auto x = memory.Snapshot(request.statics[0].address, request.statics[0].size);
            const auto a = memory.Snapshot(request.sends[0].address, request.sends[0].size);
            auto w = memory.Snapshot(request.exchanges[0].address, request.exchanges[0].size);
            std::vector<std::byte> b(a.rbegin(), a.rend());
            b.resize(request.receives[0].size);
            for (auto& byte : w)
                byte = static_cast<std::byte>(static_cast<uint8_t>(byte) + 1);
            memory.Write(request.receives[0].address, b);
            memory.Write(request.exchanges[0].address, w);
            std::vector<std::byte> x_reversed(x.rbegin(), x.rend());
            memory.Write(reply_static, x_reversed);
            reply.data = {static_cast<uint32_t>(x.size())};
            reply.statics = {{reply_static, x.size(), 0}};
            break;
        }
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
        with_receive_list(reply);
        WriteMessage(memory, tls, reply);
        reply_target = handles[index];
    }
}

} // namespace echo
