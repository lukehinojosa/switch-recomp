"""Check the lifter against unicorn, one instruction at a time.

Every distinct straight-line or conditional-branch instruction word in the
module's text is lifted on its own and run from random starting states, both
as lifted C++ (tests/difftest/harness.cpp) and in unicorn. Registers, flags,
vector registers, branch outcome and every changed scratch byte must match.
States where unicorn faults (a random address outside the mapped memory) are
dropped before the C++ side runs them.

Usage: python tools/difftest.py <module.elf> <workdir> [--states N] [--limit N] [--simd | --integer]
"""
import argparse
import random
import struct
import subprocess
import sys
import time
from pathlib import Path

from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as A

sys.path.insert(0, str(Path(__file__).parent))
import lift  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = 0x10000000
SCRATCH_SIZE = 0x10000
# One CLREX, run before each case: unicorn keeps its exclusive monitor across
# runs, and the lifted side starts every case with it clear.
CLREX_PAGE = 0x20000000
CLREX = 0xD503305F
STATE = struct.Struct("<31QQQ64QQQ")
XREGS = [getattr(A, f"UC_ARM64_REG_X{i}") for i in range(31)]
QREGS = [getattr(A, f"UC_ARM64_REG_Q{i}") for i in range(32)]
NICE_DOUBLES = [0.0, -0.0, 1.0, -1.5, 2.5, 100.0, 1e10, -3e-5, 0.5, 4294967296.0, -9.2e18, float("inf")]
# Single-precision bit patterns: ordinary values, +-0, +-inf, quiet and
# signalling NaNs with payloads, the smallest and largest subnormal, the
# largest finite, and values around the integer conversion limits.
NICE_FLOATS = [0x00000000, 0x80000000, 0x3F800000, 0xBFC00000, 0x40200000, 0x42C80000, 0x501502F9, 0xB7FBA882,
               0x7F800000, 0xFF800000, 0x7FC00000, 0xFFC12345, 0x7F800001, 0x7FA00042, 0x00000001, 0x007FFFFF,
               0x7F7FFFFF, 0x4F000000, 0xCF000000, 0x4F800000, 0x5F000000, 0x3EAAAAAB, 0x3F7FFFFF, 0x00800000]
# Double-precision patterns that random doubles rarely hit.
NICE_DOUBLE_BITS = [0x7FF8000000000000, 0xFFF0000000000001, 0x7FF4000000000042, 0x0000000000000001,
                    0x000FFFFFFFFFFFFF, 0x7FEFFFFFFFFFFFFF, 0x0010000000000000, 0x43E0000000000000]


def random_vector(rng):
    r = rng.random()
    if r < 0.3:
        lanes = [rng.choice(NICE_FLOATS) if rng.random() < 0.7 else
                 struct.unpack("<I", struct.pack("<f", rng.choice(NICE_DOUBLES[:-1]) * rng.choice([1, 3, -7])))[0]
                 for _ in range(4)]
        return lanes[0] | lanes[1] << 32, lanes[2] | lanes[3] << 32
    if r < 0.55:
        halves = []
        for _ in range(2):
            if rng.random() < 0.3:
                halves.append(rng.choice(NICE_DOUBLE_BITS))
            else:
                halves.append(struct.unpack("<Q", struct.pack("<d", rng.choice(NICE_DOUBLES) * rng.choice([1, 3, -7])))[0])
        return halves[0], halves[1]
    return rng.getrandbits(64), rng.getrandbits(64)


def random_state(rng, w):
    x = []
    for _ in range(31):
        r = rng.random()
        if r < 0.5:
            x.append(SCRATCH + SCRATCH_SIZE // 2 + rng.randrange(-0x40, 0x40) * 16)
        elif r < 0.75:
            x.append(rng.randrange(0, 64))
        else:
            x.append(rng.getrandbits(64))
    sp = SCRATCH + SCRATCH_SIZE // 2 + rng.randrange(-0x40, 0x40) * 16
    nzcv = rng.randrange(16) << 28
    q = []
    for _ in range(32):
        lo, hi = random_vector(rng)
        q += [lo, hi]
    if lift.bits(w, 28, 25) & 0b0101 == 0b0100 and rng.random() < 0.5:
        # A load or store: put the base near the bottom of scratch so large
        # positive offsets stay inside it, and keep a register index small.
        base = SCRATCH + 0x200 + rng.randrange(0, 0x20) * 16
        rn = lift.bits(w, 9, 5)
        if rn == 31:
            sp = base
        else:
            x[rn] = base
        rm = lift.bits(w, 20, 16)
        if rm != 31 and rm != rn:
            x[rm] = rng.randrange(0, 64)
    return [*x, sp, nzcv, *q, rng.getrandbits(64), rng.getrandbits(64)]


def unicorn_run(uc, pc, state, scratch, writes):
    x, sp, nzcv = state[:31], state[31], state[32]
    q = state[33:97]
    for i in range(31):
        uc.reg_write(XREGS[i], x[i])
    uc.reg_write(A.UC_ARM64_REG_SP, sp)
    uc.reg_write(A.UC_ARM64_REG_NZCV, nzcv)
    for i in range(32):
        uc.reg_write(QREGS[i], q[2 * i] | q[2 * i + 1] << 64)
    uc.reg_write(A.UC_ARM64_REG_TPIDR_EL0, state[97])
    uc.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0, state[98])
    uc.emu_start(CLREX_PAGE, CLREX_PAGE + 4, count=1)
    writes.clear()
    uc.emu_start(pc, pc + 0x1000, count=1)
    out = [uc.reg_read(r) for r in XREGS]
    out.append(uc.reg_read(A.UC_ARM64_REG_SP))
    out.append(uc.reg_read(A.UC_ARM64_REG_NZCV) & 0xF0000000)
    for r in QREGS:
        v = uc.reg_read(r)
        out += [v & lift.M64, v >> 64]
    out.append(uc.reg_read(A.UC_ARM64_REG_TPIDR_EL0))
    out.append(uc.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0))
    taken = uc.reg_read(A.UC_ARM64_REG_PC) != pc + 4
    changed = {}
    for addr, size in writes:
        for a in range(addr, addr + size):
            if SCRATCH <= a < SCRATCH + SCRATCH_SIZE:
                b = uc.mem_read(a, 1)[0]
                if b != scratch[a - SCRATCH]:
                    changed[a - SCRATCH] = b
                else:
                    changed.pop(a - SCRATCH, None)
    if writes:
        lo = min(a for a, _ in writes)
        hi = max(a + s for a, s in writes)
        lo, hi = max(lo, SCRATCH), min(hi, SCRATCH + SCRATCH_SIZE)
        if lo < hi:
            uc.mem_write(lo, bytes(scratch[lo - SCRATCH:hi - SCRATCH]))
    return out, taken, changed


def is_simd(w):
    """Floating point and Advanced SIMD, including their loads and stores."""
    return lift.bits(w, 28, 25) & 0b0111 == 0b0111 or lift.bits(w, 28, 25) & 0b0101 == 0b0100 and lift.bits(w, 26, 26)


def select_words(lifter, limit, simd_only=False, integer_only=False):
    img = lifter.image
    chosen = {}
    for pc in range(img.text_base, img.text_end, 4):
        w = img.word(pc)
        if w in chosen or (simd_only and not is_simd(w)) or (integer_only and is_simd(w)):
            continue
        i = lifter.decoder.decode(pc, w)
        if i.kind == "op":
            text = " ".join(i.code)
            if "CounterTicks" in text or "c.fpcr" in text or "c.fpsr" in text or "atomic_thread_fence" in text:
                continue
            chosen[w] = (pc, i)
        elif i.kind == "cond":
            chosen[w] = (pc, i)
    items = sorted(chosen.items(), key=lambda kv: kv[1][0])
    if limit:
        items = random.Random(1).sample(items, min(limit, len(items)))
    return items


def write_tests(items, path):
    out = ['#include "rt/ops.h"', "using namespace rt::types;", "using TestFunction = bool (*)(rt::Cpu&);", ""]
    for n, (w, (pc, i)) in enumerate(items):
        out.append(f"static bool t{n}(rt::Cpu& c) {{ // {pc:x}: {w:08x}")
        if i.kind == "op":
            out += ["    " + s for s in i.code]
            out.append("    return false;")
        else:
            out.append(f"    return {i.cond};")
        out.append("}")
    out.append("extern const TestFunction difftest_functions[] = {")
    out += [f"    t{n}," for n in range(len(items))]
    out.append("};")
    out.append(f"extern const size_t difftest_count = {len(items)};")
    path.write_text("\n".join(out) + "\n")


def build(work, tests_cpp):
    exe = work / "difftest_harness.exe"
    cmd = ["clang++", "-std=c++20", "-O1", "-w", f"-I{ROOT / 'include'}",
           str(ROOT / "tests" / "difftest" / "harness.cpp"), str(tests_cpp), "-o", str(exe)]
    subprocess.run(cmd, check=True)
    return exe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("work")
    ap.add_argument("--states", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    kind = ap.add_mutually_exclusive_group()
    kind.add_argument("--simd", action="store_true", help="only floating-point and SIMD instructions")
    kind.add_argument("--integer", action="store_true", help="only the others")
    args = ap.parse_args()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)

    image = lift.Image(args.elf)
    lifter = lift.Lifter(image)
    items = select_words(lifter, args.limit, args.simd, args.integer)
    print(f"{len(items)} distinct instruction words")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.reg_write(A.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    for va, blob, memsz, _ in image.segments:
        lo, hi = va & ~0xFFF, (va + memsz + 0xFFF) & ~0xFFF
        uc.mem_map(lo, hi - lo)
        uc.mem_write(va, blob)
    uc.mem_map(SCRATCH, SCRATCH_SIZE)
    uc.mem_map(CLREX_PAGE, 0x1000)
    uc.mem_write(CLREX_PAGE, struct.pack("<I", CLREX))
    rng = random.Random(args.seed)
    scratch = bytearray(rng.getrandbits(8) for _ in range(SCRATCH_SIZE))
    uc.mem_write(SCRATCH, bytes(scratch))
    writes = []
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, acc, addr, size, val, d: writes.append((addr, size)))

    started = time.time()
    cases, expected = [], []
    for n, (w, (pc, i)) in enumerate(items):
        # Every word runs at its own address, so unicorn translates a new
        # block each time; past about 240,000 its translation buffer
        # overflows and it crashes. Start afresh now and then.
        if n % 20000 == 0:
            uc.ctl_flush_tb()
        for _ in range(args.states):
            state = random_state(rng, w)
            try:
                result = unicorn_run(uc, pc, state, scratch, writes)
            except UcError:
                if writes:
                    uc.mem_write(SCRATCH, bytes(scratch))
                continue
            cases.append((n, state))
            expected.append(result)
    print(f"{len(cases)} cases from unicorn in {time.time() - started:.0f}s")

    write_tests(items, work / "tests.cpp")
    started = time.time()
    exe = build(work, work / "tests.cpp")
    print(f"built in {time.time() - started:.0f}s")

    blob = bytearray(struct.pack("<II", 0x54464944, len(image.segments)))
    for va, data, memsz, _ in image.segments:
        blob += struct.pack("<QQ", va, len(data)) + data
    blob += struct.pack("<QI", SCRATCH, SCRATCH_SIZE) + scratch
    blob += struct.pack("<I", len(cases))
    for n, state in cases:
        blob += struct.pack("<I", n) + STATE.pack(*state)
    (work / "cases.bin").write_bytes(blob)
    subprocess.run([str(exe), str(work / "cases.bin"), str(work / "results.bin")], check=True)

    res = (work / "results.bin").read_bytes()
    at = 0
    failures = {}
    names = ["x%d" % i for i in range(31)] + ["sp", "nzcv"] + \
        [f"q{i // 2}.{'hi' if i % 2 else 'lo'}" for i in range(64)] + ["tpidr", "tpidrro"]
    for (n, state), (want, want_taken, want_mem) in zip(cases, expected):
        got = list(STATE.unpack_from(res, at))
        at += STATE.size
        taken = res[at]
        at += 1
        count = struct.unpack_from("<I", res, at)[0]
        at += 4
        mem = {}
        for _ in range(count):
            off, b = struct.unpack_from("<IB", res, at)
            at += 5
            mem[off] = b
        diffs = [f"{names[j]}: want {want[j]:#x} got {got[j]:#x}" for j in range(len(want)) if want[j] != got[j]]
        if bool(taken) != want_taken:
            diffs.append(f"taken: want {want_taken} got {bool(taken)}")
        if mem != want_mem:
            diffs.append(f"memory: want {sorted(want_mem.items())[:6]} got {sorted(mem.items())[:6]}")
        if diffs:
            failures.setdefault(n, (state, diffs))

    tested = {n for n, _ in cases}
    print(f"{len(tested)} words exercised, {len(items) - len(tested)} never ran without faulting in unicorn")
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for n in sorted(set(range(len(items))) - tested)[:20]:
        w, (pc, i) = items[n]
        text = next((f"{d.mnemonic} {d.op_str}" for d in md.disasm(struct.pack("<I", w), pc)), "?")
        print(f"untested {pc:x} {w:08x} {text}")
    for n, (state, diffs) in sorted(failures.items())[:40]:
        w, (pc, i) = items[n]
        text = next((f"{d.mnemonic} {d.op_str}" for d in md.disasm(struct.pack("<I", w), pc)), "?")
        print(f"FAIL {pc:x} {w:08x} {text}: " + "; ".join(diffs[:4]))
    print(f"{len(failures)} failing words")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
