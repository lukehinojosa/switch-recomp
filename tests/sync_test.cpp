// Kernel synchronization tests: events, thread handles, cancellation and the
// address arbiter behind guest mutexes and condition variables. Two host
// threads act as two guest threads of one process, driving the kernel only
// through hk_svc, and play the guest userland's part of the mutex protocol
// (the word holds the owner's handle, plus 0x40000000 while others wait).
#include "hk/native.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

using namespace hk::result;

namespace {

int failures = 0;

#define CHECK(condition)                                                                     \
    do {                                                                                     \
        if (!(condition)) {                                                                  \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                                      \
        }                                                                                    \
    } while (0)

constexpr uint64_t Base = 0x10000000;
constexpr uint64_t TlsA = Base, TlsB = Base + 0x200;
constexpr uint64_t Mutex = Base + 0x400, Key = Base + 0x404, List = Base + 0x410;
constexpr uint32_t HasWaiters = 0x40000000;

struct World {
    World() {
        process = kernel.CreateProcess(0x60, memory);
        a = kernel.CreateThread(process, TlsA);
        b = kernel.CreateThread(process, TlsB);
        handle_a = kernel.AddThreadHandle(a);
        handle_b = kernel.AddThreadHandle(b);
    }
    ~World() {
        if (a)
            kernel.DestroyThread(a);
        if (b)
            kernel.DestroyThread(b);
        kernel.DestroyProcess(process);
    }
    uint32_t Word(uint64_t address) { return memory.Word(address); }
    void SetWord(uint64_t address, uint32_t value) { memory.WriteWords(address, std::span(&value, 1)); }

    // Polls until predicate holds: the other thread has reached its wait.
    template <class P>
    static bool Eventually(P predicate) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!predicate()) {
            if (std::chrono::steady_clock::now() > deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    hk::Kernel kernel;
    FlatMemory memory{Base, 0x1000};
    std::shared_ptr<hk::Process> process;
    hk_thread *a{}, *b{};
    uint32_t handle_a{}, handle_b{};
};

void EventWakesWaiter() {
    World w;
    uint32_t writable, readable;
    CHECK(svc::CreateEvent(w.a, writable, readable) == Success);
    w.memory.WriteWords(List, std::span(&readable, 1));
    std::atomic<hk::Result> waited{~0u};
    std::thread waiter([&] {
        uint32_t index = 99;
        waited = svc::WaitSynchronization(w.b, List, 1, -1, index);
        CHECK(index == 0);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(waited == ~0u);
    CHECK(svc::SignalEvent(w.a, writable) == Success);
    waiter.join();
    CHECK(waited == Success);
    CHECK(svc::ResetSignal(w.a, readable) == Success);
    CHECK(svc::ResetSignal(w.a, readable) == InvalidState);
    CHECK(svc::SignalEvent(w.a, readable) == InvalidHandle); // only the writable end signals
    uint32_t index;
    CHECK(svc::WaitSynchronization(w.a, List, 1, 0, index) == TimedOut);
}

void ThreadHandleSignalsOnExit() {
    World w;
    w.memory.WriteWords(List, std::span(&w.handle_b, 1));
    uint32_t index;
    CHECK(svc::WaitSynchronization(w.a, List, 1, 0, index) == TimedOut);
    std::thread waiter([&] { CHECK(svc::WaitSynchronization(w.a, List, 1, -1, index) == Success); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    w.kernel.DestroyThread(w.b);
    w.b = nullptr;
    waiter.join();
    CHECK(index == 0);
}

void CancelEndsWait() {
    World w;
    uint32_t writable, readable;
    CHECK(svc::CreateEvent(w.a, writable, readable) == Success);
    w.memory.WriteWords(List, std::span(&readable, 1));
    std::atomic<hk::Result> waited{~0u};
    std::thread waiter([&] {
        uint32_t index;
        waited = svc::WaitSynchronization(w.b, List, 1, -1, index);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(svc::CancelSynchronization(w.a, w.handle_b) == Success);
    waiter.join();
    CHECK(waited == Cancelled);
}

void UnlockHandsMutexToWaiter() {
    World w;
    w.SetWord(Mutex, w.handle_a);              // A holds the mutex
    w.SetWord(Mutex, w.handle_a | HasWaiters); // B marks it contended, then asks the kernel
    std::atomic<hk::Result> locked{~0u};
    std::thread waiter([&] { locked = svc::ArbitrateLock(w.b, w.handle_a, Mutex, w.handle_b); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(locked == ~0u);
    CHECK(svc::ArbitrateUnlock(w.a, Mutex) == Success);
    waiter.join();
    CHECK(locked == Success);
    CHECK(w.Word(Mutex) == w.handle_b); // ownership passed directly, no waiters left
    CHECK(svc::ArbitrateUnlock(w.b, Mutex) == Success);
    CHECK(w.Word(Mutex) == 0);
}

void LockReturnsIfOwnerChanged() {
    World w;
    w.SetWord(Mutex, 0); // released before B reached the kernel: B retries in userland
    CHECK(svc::ArbitrateLock(w.b, w.handle_a, Mutex, w.handle_b) == Success);
    CHECK(svc::ArbitrateLock(w.b, w.handle_a, Mutex + 2, w.handle_b) == InvalidAddress);
}

void ConditionVariableRoundTrip() {
    World w;
    w.SetWord(Mutex, w.handle_b); // B holds the mutex and waits on the key
    std::atomic<hk::Result> waited{~0u};
    std::thread waiter([&] { waited = svc::WaitProcessWideKeyAtomic(w.b, Mutex, Key, w.handle_b, -1); });
    // The wait releases the mutex and marks the key.
    CHECK(World::Eventually([&] { return w.Word(Mutex) == 0 && w.Word(Key) == 1; }));
    w.SetWord(Mutex, w.handle_a); // A takes the mutex, then signals
    CHECK(svc::SignalProcessWideKey(w.a, Key, 1) == Success);
    CHECK(w.Word(Key) == 0);
    // B is now queued for the mutex A holds.
    CHECK(w.Word(Mutex) == (w.handle_a | HasWaiters));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(waited == ~0u);
    CHECK(svc::ArbitrateUnlock(w.a, Mutex) == Success);
    waiter.join();
    CHECK(waited == Success);
    CHECK(w.Word(Mutex) == w.handle_b);
}

void SignalTakesFreeMutexForWaiter() {
    World w;
    w.SetWord(Mutex, w.handle_b);
    std::atomic<hk::Result> waited{~0u};
    std::thread waiter([&] { waited = svc::WaitProcessWideKeyAtomic(w.b, Mutex, Key, w.handle_b, -1); });
    CHECK(World::Eventually([&] { return w.Word(Key) == 1; }));
    CHECK(svc::SignalProcessWideKey(w.a, Key, -1) == Success); // mutex is free: B gets it at once
    waiter.join();
    CHECK(waited == Success);
    CHECK(w.Word(Mutex) == w.handle_b);
}

void ConditionWaitTimesOut() {
    World w;
    w.SetWord(Mutex, w.handle_b);
    CHECK(svc::WaitProcessWideKeyAtomic(w.b, Mutex, Key, w.handle_b, 5'000'000) == TimedOut);
    CHECK(w.Word(Mutex) == 0); // released by the wait, not re-taken on timeout
    CHECK(svc::SignalProcessWideKey(w.a, Key, 1) == Success); // nobody left to wake
    CHECK(w.Word(Key) == 0);
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*run)();
    } tests[] = {
        {"EventWakesWaiter", EventWakesWaiter},
        {"ThreadHandleSignalsOnExit", ThreadHandleSignalsOnExit},
        {"CancelEndsWait", CancelEndsWait},
        {"UnlockHandsMutexToWaiter", UnlockHandsMutexToWaiter},
        {"LockReturnsIfOwnerChanged", LockReturnsIfOwnerChanged},
        {"ConditionVariableRoundTrip", ConditionVariableRoundTrip},
        {"SignalTakesFreeMutexForWaiter", SignalTakesFreeMutexForWaiter},
        {"ConditionWaitTimesOut", ConditionWaitTimesOut},
    };
    for (const auto& test : tests) {
        const int before = failures;
        test.run();
        std::printf("%s %s\n", failures == before ? "PASS" : "FAIL", test.name);
    }
    std::printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
