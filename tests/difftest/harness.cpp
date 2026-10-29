// Runs lifted single-instruction tests on states prepared by tools/difftest.py
// and writes the resulting states back for comparison against an emulator.
//
// Usage: difftest_harness <cases.bin> <results.bin>
#include "rt/ops.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

using TestFunction = bool (*)(rt::Cpu&);
extern const TestFunction difftest_functions[];
extern const size_t difftest_count;

namespace rt {
void Call(Cpu&, u64 target) {
    std::fprintf(stderr, "unexpected call to %llx\n", static_cast<unsigned long long>(target));
    std::exit(2);
}
void Svc(Cpu&, u32, u64) { std::exit(2); }
u64 CounterTicks() { return 0; }
void Unimplemented(Cpu&, u64 pc, u32 word) {
    std::fprintf(stderr, "unimplemented %08x at %llx\n", word, static_cast<unsigned long long>(pc));
    std::exit(2);
}
void BadJump(Cpu&, u64, u64) { std::exit(2); }
} // namespace rt

namespace {

struct State {
    uint64_t x[31];
    uint64_t sp;
    uint64_t nzcv;
    uint64_t q[64];
    uint64_t tpidr;
    uint64_t tpidrro;
};

template <class T>
T Take(const std::vector<uint8_t>& in, size_t& at) {
    T v;
    std::memcpy(&v, in.data() + at, sizeof v);
    at += sizeof v;
    return v;
}

uint8_t* Commit(uint8_t* base, uint64_t address, uint64_t size) {
    uint64_t page = address & ~uint64_t{0xffff};
    uint64_t end = (address + size + 0xffff) & ~uint64_t{0xffff};
    if (!VirtualAlloc(base + page, end - page, MEM_COMMIT, PAGE_READWRITE)) {
        std::fprintf(stderr, "commit failed at %llx\n", static_cast<unsigned long long>(address));
        std::exit(2);
    }
    return base + address;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    std::vector<uint8_t> in;
    if (FILE* f = std::fopen(argv[1], "rb")) {
        uint8_t buf[1 << 16];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) in.insert(in.end(), buf, buf + n);
        std::fclose(f);
    } else {
        return 2;
    }

    auto* mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, rt::kAddressMask + 1, MEM_RESERVE, PAGE_NOACCESS));
    if (!mem) return 2;

    size_t at = 0;
    if (Take<uint32_t>(in, at) != 0x54464944) return 2; // "DIFT"
    uint32_t segments = Take<uint32_t>(in, at);
    for (uint32_t i = 0; i < segments; ++i) {
        uint64_t address = Take<uint64_t>(in, at);
        uint64_t size = Take<uint64_t>(in, at);
        std::memcpy(Commit(mem, address, size), in.data() + at, size);
        at += size;
    }
    uint64_t scratch_base = Take<uint64_t>(in, at);
    uint32_t scratch_size = Take<uint32_t>(in, at);
    uint8_t* scratch = Commit(mem, scratch_base, scratch_size);
    std::vector<uint8_t> pristine(in.begin() + at, in.begin() + at + scratch_size);
    at += scratch_size;

    uint32_t cases = Take<uint32_t>(in, at);
    FILE* out = std::fopen(argv[2], "wb");
    if (!out) return 2;
    rt::Cpu c{};
    c.mem = mem;
    for (uint32_t i = 0; i < cases; ++i) {
        uint32_t test = Take<uint32_t>(in, at);
        State s = Take<State>(in, at);
        if (test >= difftest_count) return 2;
        std::memcpy(scratch, pristine.data(), scratch_size);
        std::memcpy(c.x, s.x, sizeof c.x);
        c.sp = s.sp;
        rt::SetNzcv(c, static_cast<uint32_t>(s.nzcv >> 28));
        std::memcpy(c.q, s.q, sizeof c.q);
        c.tpidr = s.tpidr;
        c.tpidrro = s.tpidrro;
        c.excl_valid = false;

        uint8_t taken = difftest_functions[test](c) ? 1 : 0;

        std::memcpy(s.x, c.x, sizeof c.x);
        s.sp = c.sp;
        s.nzcv = uint64_t{c.nf} << 31 | uint64_t{c.zf} << 30 | uint64_t{c.cf} << 29 | uint64_t{c.vf} << 28;
        std::memcpy(s.q, c.q, sizeof c.q);
        s.tpidr = c.tpidr;
        s.tpidrro = c.tpidrro;
        std::fwrite(&s, sizeof s, 1, out);
        std::fwrite(&taken, 1, 1, out);
        std::vector<uint32_t> changed;
        for (uint32_t b = 0; b < scratch_size; ++b)
            if (scratch[b] != pristine[b]) changed.push_back(b);
        uint32_t count = static_cast<uint32_t>(changed.size());
        std::fwrite(&count, sizeof count, 1, out);
        for (uint32_t b : changed) {
            std::fwrite(&b, sizeof b, 1, out);
            std::fwrite(&scratch[b], 1, 1, out);
        }
    }
    std::fclose(out);
    return 0;
}
