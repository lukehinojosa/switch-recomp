"""Statically recompile an AArch64 Horizon module into C++.

Input is the relocated ELF that tools/nso.py writes. Output is a directory of
C++ sources against include/rt/ops.h: one function per discovered guest entry
point, plus a table that maps guest addresses to those functions for indirect
calls. The generated code and its input stay on the user's machine.

Model:
  - Guest registers and flags live in rt::Cpu. Guest memory is one flat host
    reservation, so a load is a masked add and a memcpy.
  - Every guest function becomes a host function. BL and BLR are host calls
    that set x30 first; RET is a host return. A branch to another entry is a
    tail call. Branches inside a function are gotos.
  - BR through a recognised jump table becomes a switch over its targets. Any
    other BR is a tail call through the address table.
  - Floating point covers S and D registers (FPCR rounding and flush-to-zero
    modes are not modelled: the host's defaults, round to nearest and
    subnormals kept, are the console's too), and Advanced SIMD the forms the
    targets so far use; tools/difftest.py checks each against unicorn.
  - Instructions the decoder does not know become rt::Unimplemented traps, and
    are counted in the report, so a partial lift still builds.
"""
import argparse
import re
import struct
import sys
from collections import Counter
from pathlib import Path

M64 = (1 << 64) - 1


def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


def sext(v, n):
    return v - (1 << n) if v & (1 << (n - 1)) else v


def ones(n):
    return (1 << n) - 1


def ror(v, r, n):
    r %= n
    return ((v >> r) | (v << (n - r))) & ones(n) if r else v


def decode_bit_masks(n, imms, immr, width):
    """AArch64 DecodeBitMasks for logical immediates; returns wmask or None."""
    length = (n << 6 | (~imms & 0x3f)).bit_length() - 1
    if length < 1:
        return None
    levels = ones(length)
    if (imms & levels) == levels:
        return None
    s = imms & levels
    r = immr & levels
    esize = 1 << length
    welem = ones(s + 1)
    elem = ror(welem, r, esize)
    out = 0
    for i in range(width // esize):
        out |= elem << (i * esize)
    return out


def vfp_expand_imm64(imm8):
    sign = imm8 >> 7
    b = (imm8 >> 6) & 1
    exp = ((b ^ 1) << 10) | ((ones(8) if b else 0) << 2) | ((imm8 >> 4) & 3)
    frac = (imm8 & 15) << 48
    return sign << 63 | exp << 52 | frac


def vfp_expand_imm32(imm8):
    sign = imm8 >> 7
    b = (imm8 >> 6) & 1
    exp = ((b ^ 1) << 7) | ((ones(5) if b else 0) << 2) | ((imm8 >> 4) & 3)
    frac = (imm8 & 15) << 19
    return sign << 31 | exp << 23 | frac


def advsimd_expand_imm(op, cmode, imm8):
    """AdvSIMDExpandImm for MOVI, MVNI, ORR, BIC and FMOV (vector, immediate):
    ("set" | "orr" | "bic", 64-bit pattern), or None."""
    def rep(v, width):
        out = 0
        for i in range(64 // width):
            out |= v << (i * width)
        return out

    kind = "set"
    if cmode >> 1 in (0, 1, 2, 3):  # 32-bit shifted
        shift = 8 * (cmode >> 1)
        value = rep(imm8 << shift, 32)
        if cmode & 1:
            kind = "bic" if op else "orr"
        elif op:
            value ^= ones(64)
    elif cmode >> 1 in (4, 5):  # 16-bit shifted
        shift = 8 * ((cmode >> 1) & 1)
        value = rep(imm8 << shift, 16)
        if cmode & 1:
            kind = "bic" if op else "orr"
        elif op:
            value ^= ones(64)
    elif cmode in (0b1100, 0b1101):  # 32-bit shifting ones
        value = rep((imm8 << (8 * (cmode - 0b1011))) | ones(8 * (cmode - 0b1011)), 32)
        if op:
            value ^= ones(64)
    elif cmode == 0b1110 and not op:
        value = rep(imm8, 8)
    elif cmode == 0b1110:
        value = 0
        for i in range(8):
            if imm8 >> i & 1:
                value |= 0xFF << (8 * i)
    elif cmode == 0b1111 and not op:  # FMOV, single precision
        value = rep(vfp_expand_imm32(imm8), 32)
    elif cmode == 0b1111:  # FMOV, double precision
        value = vfp_expand_imm64(imm8)
    else:
        return None
    return kind, value


CONDS = [
    "c.zf", "!c.zf", "c.cf", "!c.cf", "c.nf", "!c.nf", "c.vf", "!c.vf",
    "c.cf && !c.zf", "!(c.cf && !c.zf)", "c.nf == c.vf", "c.nf != c.vf",
    "!c.zf && c.nf == c.vf", "!(!c.zf && c.nf == c.vf)", "true", "true",
]

SYSREGS = {
    0x5E82: "c.tpidr",
    0x5E83: "c.tpidrro",
    0x5A20: "c.fpcr",
    0x5A21: "c.fpsr",
}
SYSREGS_READONLY = {
    0x5F01: "rt::CounterTicks()",
    0x5F00: "u64(19200000)",
    0x5801: "u64(0x8444c004)",  # CTR_EL0, the Cortex-A57's: 64-byte lines
    0x5807: "u64(4)",           # DCZID_EL0: DC ZVA allowed, 64-byte blocks
}


class Insn:
    """One decoded instruction.

    kind: op, b, bl, cond, br, blr, ret, svc, trap.
    """

    def __init__(self, kind, code=(), target=None, cond=None, reg=None, imm=None):
        self.kind = kind
        self.code = list(code)
        self.target = target
        self.cond = cond
        self.reg = reg
        self.imm = imm


class Unsupported(Exception):
    pass


# Register access -----------------------------------------------------------


def T(sf):
    return "u64" if sf else "u32"


def S(sf):
    return "s64" if sf else "s32"


def rs(n, sf, sp=False):
    """Read register n at width sf; 31 is sp when sp is set, else zero."""
    if n == 31:
        if sp:
            return "c.sp" if sf else "u32(c.sp)"
        return "u64(0)" if sf else "u32(0)"
    return f"c.x[{n}]" if sf else f"u32(c.x[{n}])"


def wr(n, sf, expr, sp=False):
    """Write expr to register n, zero-extending 32-bit results."""
    value = expr if sf else f"u32({expr})"
    if n == 31:
        return f"c.sp = {value};" if sp else f"(void)({expr});"
    return f"c.x[{n}] = {value};"


def shifted(n, sf, kind, amount):
    v = rs(n, sf)
    if amount == 0:
        return v
    t = T(sf)
    if kind == 0:
        return f"{t}({v} << {amount})"
    if kind == 1:
        return f"{t}({v} >> {amount})"
    if kind == 2:
        return f"{t}({S(sf)}({v}) >> {amount})"
    return f"rt::Ror({v}, {amount})"


EXTEND = ["u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64"]


def extended(n, sf, option, shift):
    src = rs(n, True)
    v = f"u64(s64({EXTEND[option]}({src})))" if option >= 4 else f"u64({EXTEND[option]}({src}))"
    if shift:
        v = f"u64({v} << {shift})"
    return v if sf else f"u32({v})"


def k(v, sf):
    return f"u64(0x{v & M64:x})" if sf else f"u32(0x{v & 0xffffffff:x})"


# Decoder -------------------------------------------------------------------


class Decoder:
    def __init__(self, image):
        self.image = image  # read-only bytes for literal loads into code

    def decode(self, pc, w):
        try:
            return self._decode(pc, w)
        except Unsupported as e:
            return Insn("trap", imm=str(e) or f"{w:08x}")

    def _decode(self, pc, w):
        op0 = bits(w, 28, 25)
        if op0 in (0b1000, 0b1001):
            return self.dp_imm(pc, w)
        if op0 in (0b1010, 0b1011):
            return self.branch_sys(pc, w)
        if op0 in (0b0101, 0b1101):
            return self.dp_reg(pc, w)
        if op0 & 0b0101 == 0b0100:
            return self.ldst(pc, w)
        if op0 & 0b0111 == 0b0111:
            return self.simd(pc, w)
        if w >> 16 == 0:
            return Insn("trap", imm=f"udf #{w & 0xffff}")
        raise Unsupported()

    # Data processing, immediate ------------------------------------------

    def dp_imm(self, pc, w):
        sf = w >> 31
        rd, rn = w & 31, bits(w, 9, 5)
        cls = bits(w, 28, 23)
        if cls in (0b100000, 0b100001):  # adr, adrp
            imm = sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21)
            if w >> 31:
                value = (pc & ~0xFFF) + (imm << 12)
            else:
                value = pc + imm
            return Insn("op", [wr(rd, 1, k(value, 1))])
        if cls == 0b100010:  # add/sub immediate
            op, s, sh = bits(w, 30, 30), bits(w, 29, 29), bits(w, 22, 22)
            imm = bits(w, 21, 10) << (12 if sh else 0)
            a = rs(rn, sf, sp=True)
            if s:
                fn = f"rt::Sub{'64' if sf else '32'}F" if op else f"rt::Add{'64' if sf else '32'}F"
                return Insn("op", [wr(rd, sf, f"{fn}(c, {a}, {k(imm, sf)})")])
            expr = f"{T(sf)}({a} {'-' if op else '+'} {k(imm, sf)})"
            return Insn("op", [wr(rd, sf, expr, sp=True)])
        if cls == 0b100100:  # logical immediate
            opc, n = bits(w, 30, 29), bits(w, 22, 22)
            if not sf and n:
                raise Unsupported("logical imm N=1 in 32-bit")
            mask = decode_bit_masks(n, bits(w, 15, 10), bits(w, 21, 16), 64 if sf else 32)
            if mask is None:
                raise Unsupported("bad bitmask")
            a = rs(rn, sf)
            expr = f"{T(sf)}({a} {['&', '|', '^', '&'][opc]} {k(mask, sf)})"
            if opc == 3:
                return Insn("op", [wr(rd, sf, f"rt::LogicF(c, {expr})")])
            return Insn("op", [wr(rd, sf, expr, sp=True)])
        if cls == 0b100101:  # move wide
            opc, hw = bits(w, 30, 29), bits(w, 22, 21)
            imm = bits(w, 20, 5) << (16 * hw)
            if opc == 0:
                return Insn("op", [wr(rd, sf, k(~imm, sf))])
            if opc == 2:
                return Insn("op", [wr(rd, sf, k(imm, sf))])
            if opc == 3:
                keep = ~(0xFFFF << (16 * hw))
                return Insn("op", [wr(rd, sf, f"{T(sf)}(({rs(rd, sf)} & {k(keep, sf)}) | {k(imm, sf)})")])
            raise Unsupported()
        if cls == 0b100110:  # bitfield
            return Insn("op", [self.bitfield(w, sf, rd, rn)])
        if cls == 0b100111:  # extr
            lsb = bits(w, 15, 10)
            rm = bits(w, 20, 16)
            width = 64 if sf else 32
            if lsb == 0:
                expr = rs(rm, sf)
            else:
                expr = f"{T(sf)}(({rs(rm, sf)} >> {lsb}) | ({rs(rn, sf)} << {width - lsb}))"
            return Insn("op", [wr(rd, sf, expr)])
        raise Unsupported()

    def bitfield(self, w, sf, rd, rn):
        opc, immr, imms = bits(w, 30, 29), bits(w, 21, 16), bits(w, 15, 10)
        width = 64 if sf else 32
        t, s = T(sf), S(sf)
        src = rs(rn, sf)
        if opc == 2:  # ubfm
            if imms >= immr:
                f = imms - immr + 1
                expr = f"{t}(({src} >> {immr}) & {k(ones(f), sf)})"
            else:
                expr = f"{t}(({src} & {k(ones(imms + 1), sf)}) << {width - immr})"
            return wr(rd, sf, expr)
        if opc == 0:  # sbfm
            if imms >= immr:
                f = imms - immr + 1
                expr = f"{t}({s}({t}({src} << {width - immr - f})) >> {width - f})"
            else:
                f = imms + 1
                expr = f"{t}({t}({s}({t}({src} << {width - f})) >> {width - f}) << {width - immr})"
            return wr(rd, sf, expr)
        if opc == 1:  # bfm
            dst = rs(rd, sf)
            if imms >= immr:
                f = imms - immr + 1
                m = ones(f)
                expr = f"{t}(({dst} & {k(~m, sf)}) | (({src} >> {immr}) & {k(m, sf)}))"
            else:
                f = imms + 1
                lsb = width - immr
                m = ones(f) << lsb
                expr = f"{t}(({dst} & {k(~m, sf)}) | (({src} << {lsb}) & {k(m, sf)}))"
            return wr(rd, sf, expr)
        raise Unsupported()

    # Branches, exceptions and system -------------------------------------

    def branch_sys(self, pc, w):
        if bits(w, 30, 26) == 0b00101:
            target = (pc + (sext(bits(w, 25, 0), 26) << 2)) & M64
            return Insn("bl" if w >> 31 else "b", target=target)
        if w >> 24 == 0x54 and not w & 0x10:
            target = (pc + (sext(bits(w, 23, 5), 19) << 2)) & M64
            return Insn("cond", target=target, cond=CONDS[w & 15])
        if bits(w, 30, 25) == 0b011010:  # cbz/cbnz
            sf, rt = w >> 31, w & 31
            target = (pc + (sext(bits(w, 23, 5), 19) << 2)) & M64
            op = "!=" if bits(w, 24, 24) else "=="
            return Insn("cond", target=target, cond=f"{rs(rt, sf)} {op} 0")
        if bits(w, 30, 25) == 0b011011:  # tbz/tbnz
            bit = (w >> 31) << 5 | bits(w, 23, 19)
            rt = w & 31
            target = (pc + (sext(bits(w, 18, 5), 14) << 2)) & M64
            op = "!=" if bits(w, 24, 24) else "=="
            return Insn("cond", target=target, cond=f"(({rs(rt, 1)} >> {bit}) & 1) {op} 0")
        if w & 0xFFFFFC1F == 0xD61F0000:
            return Insn("br", reg=bits(w, 9, 5))
        if w & 0xFFFFFC1F == 0xD63F0000:
            return Insn("blr", reg=bits(w, 9, 5))
        if w & 0xFFFFFC1F == 0xD65F0000:
            return Insn("ret", reg=bits(w, 9, 5))
        if w & 0xFFE0001F == 0xD4000001:
            return Insn("svc", imm=bits(w, 20, 5))
        if w & 0xFFFFF01F == 0xD503201F:  # hints: nop, yield, xpaclri, ...
            return Insn("op", [])
        if w & 0xFFFFF0FF == 0xD503305F:  # clrex
            return Insn("op", ["c.excl_valid = false;"])
        if w & 0xFFFFF09F == 0xD503309F:  # dsb, dmb (isb is 0xdf and also lands here harmlessly)
            return Insn("op", ["std::atomic_thread_fence(std::memory_order_seq_cst);"])
        if w & 0xFFFFFFE0 == 0xD50B7420:  # dc zva: zero the 64-byte block (DCZID_EL0)
            return Insn("op", [f"{{ u64 a = {rs(w & 31, 1)} & ~u64(63); "
                               f"for (u64 i = 0; i < 64; i += 8) rt::St<u64>(c, a + i, 0); }}"])
        if w & 0xFFFFFFE0 in (0xD50B7A20, 0xD50B7B20, 0xD50B7E20, 0xD50B7520):
            # dc cvac, dc cvau, dc civac, ic ivau: host memory is coherent, and
            # no code is generated at run time
            return Insn("op", [])
        if w & 0xFFF00000 in (0xD5300000, 0xD5100000):
            key = bits(w, 19, 5)
            rt = w & 31
            if w & 0x200000:  # mrs
                src = SYSREGS.get(key) or SYSREGS_READONLY.get(key)
                if src is None:
                    raise Unsupported(f"mrs {key:#x}")
                return Insn("op", [wr(rt, 1, src)])
            dst = SYSREGS.get(key)
            if dst is None:
                raise Unsupported(f"msr {key:#x}")
            return Insn("op", [f"{dst} = {rs(rt, 1)};"])
        raise Unsupported()

    # Data processing, register -------------------------------------------

    def dp_reg(self, pc, w):
        sf = w >> 31
        rd, rn, rm = w & 31, bits(w, 9, 5), bits(w, 20, 16)
        t = T(sf)
        if w & 0x7FE0E000 == 0x1AC04000:  # CRC32B/H/W/X, CRC32CB/H/W/X
            sz, castagnoli = bits(w, 11, 10), bits(w, 12, 12)
            if (sz == 3) != bool(sf):
                raise Unsupported()
            data = rs(rm, sz == 3)
            return Insn("op", [wr(rd, 0, f"rt::Crc32({rs(rn, 0)}, u64({data}), {1 << sz}, "
                                         f"{'true' if castagnoli else 'false'})")])
        if bits(w, 28, 24) == 0b01010:  # logical shifted register
            opc, shift, n = bits(w, 30, 29), bits(w, 23, 22), bits(w, 21, 21)
            imm6 = bits(w, 15, 10)
            b = shifted(rm, sf, shift, imm6)
            if n:
                b = f"{t}(~{b})"
            a = rs(rn, sf)
            expr = f"{t}({a} {['&', '|', '^', '&'][opc]} {b})"
            if opc == 3:
                expr = f"rt::LogicF(c, {expr})"
            return Insn("op", [wr(rd, sf, expr)])
        if bits(w, 28, 24) == 0b01011:
            op, s = bits(w, 30, 30), bits(w, 29, 29)
            if bits(w, 21, 21):  # extended register
                b = extended(rm, sf, bits(w, 15, 13), bits(w, 12, 10))
                a = rs(rn, sf, sp=True)
                to_sp = not s
            else:
                b = shifted(rm, sf, bits(w, 23, 22), bits(w, 15, 10))
                a = rs(rn, sf)
                to_sp = False
            if s:
                fn = f"rt::{'Sub' if op else 'Add'}{'64' if sf else '32'}F"
                return Insn("op", [wr(rd, sf, f"{fn}(c, {a}, {b})")])
            return Insn("op", [wr(rd, sf, f"{t}({a} {'-' if op else '+'} {b})", sp=to_sp)])
        cls = bits(w, 28, 21)
        if cls == 0b11010000:  # adc/sbc
            op, s = bits(w, 30, 30), bits(w, 29, 29)
            a, b = rs(rn, sf), rs(rm, sf)
            if op:
                b = f"{t}(~{b})"
            if s:
                return Insn("op", [wr(rd, sf, f"rt::Adc{'64' if sf else '32'}F(c, {a}, {b}, c.cf)")])
            return Insn("op", [wr(rd, sf, f"{t}({a} + {b} + c.cf)")])
        if cls == 0b11010010:  # ccmp/ccmn
            op = bits(w, 30, 30)
            cond = CONDS[bits(w, 15, 12)]
            b = k(rm, sf) if bits(w, 11, 11) else rs(rm, sf)
            fn = f"rt::{'Sub' if op else 'Add'}{'64' if sf else '32'}F"
            nzcv = w & 15
            return Insn("op", [f"if ({cond}) (void){fn}(c, {rs(rn, sf)}, {b}); else rt::SetNzcv(c, {nzcv});"])
        if cls == 0b11010100:  # conditional select
            op, op2 = bits(w, 30, 30), bits(w, 11, 10)
            cond = CONDS[bits(w, 15, 12)]
            a, b = rs(rn, sf), rs(rm, sf)
            other = [b, f"{t}({b} + 1)", f"{t}(~{b})", f"{t}(0 - {b})"][op << 1 | op2]
            return Insn("op", [wr(rd, sf, f"({cond} ? {a} : {t}({other}))")])
        if cls == 0b11010110:
            if bits(w, 30, 30) == 0:  # two source
                opcode = bits(w, 15, 10)
                a, b = rs(rn, sf), rs(rm, sf)
                bitsz = 64 if sf else 32
                if opcode == 2:
                    expr = f"{t}({b} ? {a} / {b} : 0)"
                elif opcode == 3:
                    expr = f"rt::Sdiv({a}, {b})"
                elif 8 <= opcode <= 11:
                    amount = f"({b} & {bitsz - 1})"
                    expr = [f"{t}({a} << {amount})", f"{t}({a} >> {amount})",
                            f"{t}({S(sf)}({a}) >> {amount})", f"rt::Ror({a}, {amount})"][opcode - 8]
                else:
                    raise Unsupported()
                return Insn("op", [wr(rd, sf, expr)])
            opcode = bits(w, 15, 10)  # one source
            a = rs(rn, sf)
            names = {0: "Rbit", 1: "Rev16", 4: "Clz", 5: "Cls"}
            if opcode in names:
                return Insn("op", [wr(rd, sf, f"rt::{names[opcode]}({a})")])
            if opcode == 2:
                return Insn("op", [wr(rd, sf, f"rt::Rev32({a})" if sf else f"rt::Rev({a})")])
            if opcode == 3 and sf:
                return Insn("op", [wr(rd, sf, f"rt::Rev({a})")])
            raise Unsupported()
        if bits(w, 28, 24) == 0b11011:  # three source
            op31, o0 = bits(w, 23, 21), bits(w, 15, 15)
            ra = bits(w, 14, 10)
            sign = "-" if o0 else "+"
            if op31 == 0:
                expr = f"{t}({rs(ra, sf)} {sign} {t}({rs(rn, sf)} * {rs(rm, sf)}))"
            elif op31 in (1, 5):
                cast = "s32" if op31 == 1 else "u32"
                wide = "s64" if op31 == 1 else "u64"
                prod = f"u64({wide}({cast}(c.x[{rn}] & 0xffffffff)) * {wide}({cast}({rs(rm, 1)} & 0xffffffff)))"
                if rn == 31:
                    prod = "u64(0)"
                expr = f"u64({rs(ra, 1)} {sign} {prod})"
            elif op31 in (2, 6) and not o0:
                expr = f"rt::{'Smulh' if op31 == 2 else 'Umulh'}({rs(rn, 1)}, {rs(rm, 1)})"
            else:
                raise Unsupported()
            return Insn("op", [wr(rd, sf, expr)])
        raise Unsupported()

    # Loads and stores ----------------------------------------------------

    def ldst(self, pc, w):
        if bits(w, 29, 24) == 0b001000:
            return self.exclusive(w)
        if bits(w, 31, 31) == 0 and bits(w, 29, 26) == 0b0011:
            return self.structure(w)
        if bits(w, 29, 27) == 0b011 and bits(w, 25, 24) == 0:  # literal
            opc, v, rt = bits(w, 31, 30), bits(w, 26, 26), w & 31
            addr = (pc + (sext(bits(w, 23, 5), 19) << 2)) & M64
            a = k(addr, 1)
            if v:
                size = [4, 8, 16][opc]
                return Insn("op", [self.vload(rt, size, a)])
            if opc == 3:
                return Insn("op", [])  # prfm literal
            if opc == 2:
                return Insn("op", [wr(rt, 1, f"u64(s64(rt::Ld<s32>(c, {a})))")])
            return Insn("op", [wr(rt, opc, f"rt::Ld<{'u64' if opc else 'u32'}>(c, {a})")])
        if bits(w, 29, 27) == 0b101:
            return self.pair(w)
        if bits(w, 29, 27) == 0b111:
            return self.single(w)
        raise Unsupported()

    def structure(self, w):
        """Advanced SIMD loads and stores of structures: LD1-LD4 and ST1-ST4
        (multiple structures, or one lane), and LD1R-LD4R."""
        q, load, post, single = bits(w, 30, 30), bits(w, 22, 22), bits(w, 23, 23), bits(w, 24, 24)
        rm, opcode, rn, rt = bits(w, 20, 16), bits(w, 15, 12), bits(w, 9, 5), w & 31
        if not post and rm:
            raise Unsupported()
        code = [f"{{ u64 a = {rs(rn, 1, sp=True)};"]
        if not single:
            if bits(w, 21, 21):
                raise Unsupported()
            layout = {0b0000: (4, 1), 0b0010: (1, 4), 0b0100: (3, 1), 0b0110: (1, 3),
                      0b0111: (1, 1), 0b1000: (2, 1), 0b1010: (1, 2)}.get(opcode)
            if layout is None:
                raise Unsupported()
            selem, rpt = layout
            size = bits(w, 11, 10)
            if size == 3 and not q and selem > 1:
                raise Unsupported()
            ty = ["u8", "u16", "u32", "u64"][size]
            esize, elements = 1 << size, (16 if q else 8) >> size
            if load:
                for r in range(rpt * selem):
                    code.append(f"rt::Vec v{r}{{0, 0}};")
            offset = 0
            for r in range(rpt):
                for e in range(elements):
                    for s_ in range(selem):
                        reg = r * selem + s_ if selem > 1 else r
                        if load:
                            code.append(f"v{reg} = rt::VIns(v{reg}, {size}, {e}, u64(rt::Ld<{ty}>(c, a + {offset})));")
                        else:
                            code.append(f"rt::St<{ty}>(c, a + {offset}, "
                                        f"{ty}(rt::VLane(c.q[{(rt + reg) % 32}], {size}, {e})));")
                        offset += esize
            if load:
                for r in range(rpt * selem):
                    code.append(f"c.q[{(rt + r) % 32}] = v{r};")
            total = offset
        else:
            r_bit, s_bit, size_field = bits(w, 21, 21), bits(w, 12, 12), bits(w, 11, 10)
            scale = bits(w, 15, 14)
            selem = ((bits(w, 13, 13) << 1) | r_bit) + 1
            if scale == 3:  # LDnR
                if not load or s_bit:
                    raise Unsupported()
                size = size_field
                ty = ["u8", "u16", "u32", "u64"][size]
                for s_ in range(selem):
                    code.append(f"c.q[{(rt + s_) % 32}] = rt::Narrow(rt::VDup(u64(rt::Ld<{ty}>(c, a + {s_ << size})), "
                                f"{size}, 1), {q});")
                total = selem << size
            else:
                size = scale
                if size == 0:
                    index = q << 3 | s_bit << 2 | size_field
                elif size == 1:
                    if size_field & 1:
                        raise Unsupported()
                    index = q << 2 | s_bit << 1 | size_field >> 1
                elif size_field == 0:
                    size, index = 2, q << 1 | s_bit
                elif size_field == 1 and not s_bit:
                    size, index = 3, q
                else:
                    raise Unsupported()
                ty = ["u8", "u16", "u32", "u64"][size]
                for s_ in range(selem):
                    reg = (rt + s_) % 32
                    if load:
                        code.append(f"c.q[{reg}] = rt::VIns(c.q[{reg}], {size}, {index}, "
                                    f"u64(rt::Ld<{ty}>(c, a + {s_ << size})));")
                    else:
                        code.append(f"rt::St<{ty}>(c, a + {s_ << size}, {ty}(rt::VLane(c.q[{reg}], {size}, {index})));")
                total = selem << size
        if post:
            step = k(total, 1) if rm == 31 else rs(rm, 1)
            code.append(wr(rn, 1, f"u64(a + {step})", sp=True))
        code.append("}")
        return Insn("op", [" ".join(code)])

    def vload(self, rt, size, a):
        if size == 16:
            return f"c.q[{rt}] = rt::Ld<rt::Vec>(c, {a});"
        return f"c.q[{rt}] = rt::Vec{{u64(rt::Ld<{['u8', 'u16', 'u32', 'u64'][size.bit_length() - 1]}>(c, {a})), 0}};"

    def vstore(self, rt, size, a):
        if size == 16:
            return f"rt::St<rt::Vec>(c, {a}, c.q[{rt}]);"
        ty = ["u8", "u16", "u32", "u64"][size.bit_length() - 1]
        return f"rt::St<{ty}>(c, {a}, {ty}(c.q[{rt}].lo));"

    def single(self, w):
        size, v, opc = bits(w, 31, 30), bits(w, 26, 26), bits(w, 23, 22)
        rn, rt = bits(w, 9, 5), w & 31
        base = rs(rn, 1, sp=True)
        post = pre = None
        if bits(w, 25, 24) == 0b01:  # unsigned offset
            if v:
                scale = 4 if opc & 2 else size
            else:
                scale = size
            addr = f"u64({base} + {bits(w, 21, 10) << scale})"
        elif bits(w, 21, 21) == 0:
            imm = sext(bits(w, 20, 12), 9)
            idx = bits(w, 11, 10)
            if idx == 0b10:
                raise Unsupported("unprivileged")
            if idx == 0b01:
                addr = base
                post = imm
            elif idx == 0b11:
                addr = f"u64({base} + {k(imm, 1)})"
                pre = True
            else:
                addr = f"u64({base} + {k(imm, 1)})"
        elif bits(w, 11, 10) == 0b10:  # register offset
            option, s = bits(w, 15, 13), bits(w, 12, 12)
            scale = (4 if opc & 2 else size) if v else size
            off = extended(bits(w, 20, 16), 1, option, scale if s else 0)
            addr = f"u64({base} + {off})"
        else:
            raise Unsupported()

        if v:
            nbytes = 16 if opc & 2 else 1 << size
            body = self.vload(rt, nbytes, "a") if opc & 1 else self.vstore(rt, nbytes, "a")
        else:
            ty = ["u8", "u16", "u32", "u64"][size]
            sty = ["s8", "s16", "s32", "s64"][size]
            if opc == 0:
                body = f"rt::St<{ty}>(c, a, {ty}({rs(rt, 1)}));"
            elif opc == 1:
                body = wr(rt, 1, f"u64(rt::Ld<{ty}>(c, a))")
            elif size == 3:
                return Insn("op", [])  # prfm, prfum
            elif opc == 2:
                body = wr(rt, 1, f"u64(s64(rt::Ld<{sty}>(c, a)))")
            else:
                if size == 2:
                    raise Unsupported()
                body = wr(rt, 0, f"u32(s32(rt::Ld<{sty}>(c, a)))")
        code = [f"{{ u64 a = {addr};", body]
        if pre:
            code.append(wr(rn, 1, "a", sp=True))
        if post is not None:
            code.append(wr(rn, 1, f"u64(a + {k(post, 1)})", sp=True))
        code.append("}")
        return Insn("op", [" ".join(code)])

    def pair(self, w):
        opc, v, l = bits(w, 31, 30), bits(w, 26, 26), bits(w, 22, 22)
        mode = bits(w, 25, 23)
        rt2, rn, rt = bits(w, 14, 10), bits(w, 9, 5), w & 31
        if v:
            size = [4, 8, 16, None][opc]
        else:
            size = [4, 4, 8, None][opc]
        if size is None or (opc == 1 and not v and not l):
            raise Unsupported()
        imm = sext(bits(w, 21, 15), 7) * size
        base = rs(rn, 1, sp=True)
        if mode == 0b001:
            addr = base
        elif mode in (0b010, 0b011, 0b000):
            addr = f"u64({base} + {k(imm, 1)})"
        else:
            raise Unsupported()
        code = [f"{{ u64 a = {addr};"]
        if v:
            if l:
                ty = "rt::Vec" if size == 16 else ("u64" if size == 8 else "u32")
                if size == 16:
                    code.append(f"rt::Vec t0 = rt::Ld<rt::Vec>(c, a); rt::Vec t1 = rt::Ld<rt::Vec>(c, a + 16);")
                    code.append(f"c.q[{rt}] = t0; c.q[{rt2}] = t1;")
                else:
                    code.append(f"{ty} t0 = rt::Ld<{ty}>(c, a); {ty} t1 = rt::Ld<{ty}>(c, a + {size});")
                    code.append(f"c.q[{rt}] = rt::Vec{{u64(t0), 0}}; c.q[{rt2}] = rt::Vec{{u64(t1), 0}};")
            else:
                code.append(self.vstore(rt, size, "a"))
                code.append(self.vstore(rt2, size, f"a + {size}"))
        else:
            ty = "u64" if size == 8 else "u32"
            if l:
                if opc == 1:
                    code.append(f"u64 t0 = u64(s64(rt::Ld<s32>(c, a))); u64 t1 = u64(s64(rt::Ld<s32>(c, a + 4)));")
                    code.append(wr(rt, 1, "t0"))
                    code.append(wr(rt2, 1, "t1"))
                else:
                    code.append(f"{ty} t0 = rt::Ld<{ty}>(c, a); {ty} t1 = rt::Ld<{ty}>(c, a + {size});")
                    code.append(wr(rt, size == 8, "t0"))
                    code.append(wr(rt2, size == 8, "t1"))
            else:
                code.append(f"{ty} t0 = {ty}({rs(rt, 1)}); {ty} t1 = {ty}({rs(rt2, 1)});")
                code.append(f"rt::St<{ty}>(c, a, t0); rt::St<{ty}>(c, a + {size}, t1);")
        if mode == 0b001:
            code.append(wr(rn, 1, f"u64(a + {k(imm, 1)})", sp=True))
        elif mode == 0b011:
            code.append(wr(rn, 1, "a", sp=True))
        code.append("}")
        return Insn("op", [" ".join(code)])

    def exclusive(self, w):
        size = bits(w, 31, 30)
        o2, l, o1, o0 = bits(w, 23, 23), bits(w, 22, 22), bits(w, 21, 21), bits(w, 15, 15)
        rs_, rn, rt = bits(w, 20, 16), bits(w, 9, 5), w & 31
        if o1:
            raise Unsupported("exclusive pair")
        ty = ["u8", "u16", "u32", "u64"][size]
        a = rs(rn, 1, sp=True)
        if o2:  # ldar, stlr (and the LO variants when o0 is clear)
            if l:
                return Insn("op", [wr(rt, 1, f"u64(rt::LdAcq<{ty}>(c, {a}))")])
            return Insn("op", [f"rt::StRel<{ty}>(c, {a}, {ty}({rs(rt, 1)}));"])
        if l:
            return Insn("op", [wr(rt, 1, f"u64(rt::LdExcl<{ty}>(c, {a}))")])
        return Insn("op", [wr(rs_, 0, f"rt::StExcl<{ty}>(c, {a}, {ty}({rs(rt, 1)}))")])

    # SIMD and floating point: the forms the targets use -------------------

    def simd(self, pc, w):
        rd, rn, rm = w & 31, bits(w, 9, 5), bits(w, 20, 16)
        q = bits(w, 30, 30)
        D = lambda r: f"rt::D(c.q[{r}])"
        setd = lambda r, e: f"c.q[{r}] = rt::FromD({e});"

        def m(mask, val):
            return w & mask == val

        scalar = self.scalar_fp(w, rd, rn, rm)
        if scalar:
            return scalar
        if m(0xFFFFFC00, 0x9E670000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{{rs(rn, 1)}, 0}};"])
        if m(0xFFFFFC00, 0x9E660000):
            return Insn("op", [wr(rd, 1, f"c.q[{rn}].lo")])
        if m(0xFFFFFC00, 0x1E270000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{u64({rs(rn, 0)}), 0}};"])
        if m(0xFFFFFC00, 0x1E260000):
            return Insn("op", [wr(rd, 0, f"u32(c.q[{rn}].lo)")])

        # Advanced SIMD.
        vq = f"c.q[{rd}]"
        if m(0xBF20FC00, 0x0E208400):
            return Insn("op", [f"{vq} = rt::VAdd(c.q[{rn}], c.q[{rm}], {bits(w, 23, 22)}, {q});"])
        for val, fn in ((0x0E201C00, "VAnd"), (0x0EA01C00, "VOrr"), (0x2EE01C00, "VBif")):
            if m(0xBFE0FC00, val):
                if fn == "VBif":
                    return Insn("op", [f"{vq} = rt::VBif({vq}, c.q[{rn}], c.q[{rm}], {q});"])
                return Insn("op", [f"{vq} = rt::{fn}(c.q[{rn}], c.q[{rm}], {q});"])
        if m(0xBFFFFC00, 0x2E205800):
            return Insn("op", [f"{vq} = rt::VNot(c.q[{rn}], {q});"])
        if m(0xBF20FC00, 0x2E208C00):
            return Insn("op", [f"{vq} = rt::VCmeq(c.q[{rn}], c.q[{rm}], {bits(w, 23, 22)}, {q});"])
        if m(0xBFE0FC00, 0x0E000C00):
            imm5 = bits(w, 20, 16)
            if imm5 & 15 == 0:
                raise Unsupported()
            size = (imm5 & -imm5).bit_length() - 1
            return Insn("op", [f"{vq} = rt::VDup({rs(rn, 1)}, {size}, {q});"])
        if m(0xBFE0FC00, 0x0E003C00):
            imm5 = bits(w, 20, 16)
            size = (imm5 & -imm5).bit_length() - 1
            index = imm5 >> (size + 1)
            return Insn("op", [wr(rd, size == 3, f"rt::VLane(c.q[{rn}], {size}, {index})")])
        if m(0xBFBFFC00, 0x2EA0F800) and bits(w, 22, 22):
            return Insn("op", [f"{vq} = rt::VFnegD(c.q[{rn}], {q});"])
        if m(0xBF3FFC00, 0x2E200800):
            return Insn("op", [f"{vq} = rt::VRev32(c.q[{rn}], {bits(w, 23, 22)}, {q});"])
        if m(0xBF80FC00, 0x0F008400) and bits(w, 22, 19):
            immh = bits(w, 22, 19)
            size = immh.bit_length() - 1
            shift = (16 << size) - bits(w, 22, 16)
            return Insn("op", [f"{vq} = rt::VShrn({vq}, c.q[{rn}], {size}, {shift}, {q});"])
        if m(0xBF3FFC00, 0x2E30A800) or m(0xBF3FFC00, 0x2E31A800):
            fn = "VUminv" if bits(w, 16, 16) else "VUmaxv"
            return Insn("op", [f"{vq} = rt::{fn}(c.q[{rn}], {bits(w, 23, 22)}, {q});"])
        if m(0xBFF8FC00, 0x2F00E400):
            imm8 = bits(w, 18, 16) << 5 | bits(w, 9, 5)
            value = 0
            for i in range(8):
                if imm8 >> i & 1:
                    value |= 0xFF << (8 * i)
            hi = value if q else 0
            return Insn("op", [f"{vq} = rt::Vec{{0x{value:x}ull, 0x{hi:x}ull}};"])
        if m(0xFFE0FC00, 0x5E004000):
            return Insn("op", [f"{vq} = rt::Sha256H({vq}, c.q[{rn}], c.q[{rm}]);"])
        if m(0xFFE0FC00, 0x5E005000):
            return Insn("op", [f"{vq} = rt::Sha256H2({vq}, c.q[{rn}], c.q[{rm}]);"])
        if m(0xFFE0FC00, 0x5E006000):
            return Insn("op", [f"{vq} = rt::Sha256Su1({vq}, c.q[{rn}], c.q[{rm}]);"])
        if m(0xFFFFFC00, 0x5E282800):
            return Insn("op", [f"{vq} = rt::Sha256Su0({vq}, c.q[{rn}]);"])
        neon = self.neon(w, rd, rn, rm, q)
        if neon:
            return neon
        raise Unsupported()

    def scalar_fp(self, w, rd, rn, rm):
        """Scalar floating point in S (ftype 0) and D (ftype 1) registers."""
        def m(mask, val):
            return w & mask == val

        ftype = bits(w, 23, 22)
        if bits(w, 30, 24) not in (0b0011110, 0b0011111) or bits(w, 29, 29):
            return self.scalar_simd_fp(w, rd, rn, rm)
        if ftype not in (0, 1) and not (m(0x7F3F0000, 0x1E260000) or m(0x7F3F0000, 0x1E270000)):
            return None
        ty = "float" if ftype == 0 else "double"
        get = (lambda r: f"rt::F(c.q[{r}])") if ftype == 0 else (lambda r: f"rt::D(c.q[{r}])")
        put = lambda e: f"c.q[{rd}] = rt::FromFp({ty}({e}));"
        width = 32 if ftype == 0 else 64
        lo_mask = "0xffffffffull" if ftype == 0 else "0xffffffffffffffffull"
        sign = f"0x{1 << (width - 1):x}ull"
        op = lambda *code: Insn("op", list(code))

        if bits(w, 28, 24) == 0b11111:  # FMADD, FMSUB, FNMADD, FNMSUB
            # FMADD a + n*m, FMSUB a - n*m, FNMADD -a - n*m, FNMSUB -a + n*m,
            # each negating its operands before the fused multiply-add.
            ra = bits(w, 14, 10)
            o1, o0 = bits(w, 21, 21), bits(w, 15, 15)
            n = f"rt::Neg({get(rn)})" if o0 != o1 else get(rn)
            a = f"rt::Neg({get(ra)})" if o1 else get(ra)
            return op(put(f"rt::Fmadd<{ty}>({n}, {get(rm)}, {a})"))
        if not bits(w, 21, 21):  # conversions to and from fixed point
            if m(0x7F3F0000, 0x1E180000) or m(0x7F3F0000, 0x1E190000):
                sf, fbits = w >> 31, 64 - bits(w, 15, 10)
                it = ("u64" if sf else "u32") if bits(w, 16, 16) else ("s64" if sf else "s32")
                return op(wr(rd, sf, f"{T(sf)}(rt::FcvtInt<{it}>({get(rn)}, rt::Round::Z, {fbits}))"))
            if m(0x7F3F0000, 0x1E020000) or m(0x7F3F0000, 0x1E030000):
                sf, fbits = w >> 31, 64 - bits(w, 15, 10)
                it = ("u64" if sf else "u32") if bits(w, 16, 16) else ("s64" if sf else "s32")
                return op(put(f"rt::IntToFp<{ty}>({it}({rs(rn, sf)}), {fbits})"))
            return None
        if m(0x7F20FC00, 0x1E200000) and bits(w, 21, 21):  # to and from general registers
            sf, rmode, opcode = w >> 31, bits(w, 20, 19), bits(w, 18, 16)
            if opcode in (0, 1, 4, 5):  # FCVT[NPMZA][SU]
                mode = {0: "N", 1: "P", 2: "M", 3: "Z"}[rmode] if opcode < 4 else "A"
                if opcode >= 4 and rmode:
                    return None
                it = ("u64" if sf else "u32") if opcode & 1 else ("s64" if sf else "s32")
                return op(wr(rd, sf, f"{T(sf)}(rt::FcvtInt<{it}>({get(rn)}, rt::Round::{mode}))"))
            if opcode in (2, 3) and rmode == 0:  # SCVTF, UCVTF
                it = ("u64" if sf else "u32") if opcode & 1 else ("s64" if sf else "s32")
                return op(put(f"rt::IntToFp<{ty}>({it}({rs(rn, sf)}))"))
            if opcode in (6, 7) and rmode == 0 and sf == (ftype == 1):  # FMOV
                if opcode == 6:
                    return op(wr(rd, sf, f"{T(sf)}(c.q[{rn}].lo)"))
                return op(f"c.q[{rd}] = rt::Vec{{u64({rs(rn, sf)}), 0}};")
            return None
        if w >> 31:
            return None
        if m(0xFF3E7C00, 0x1E204000):  # FMOV, FABS, FNEG, FSQRT (register)
            kind = bits(w, 16, 15)
            if kind == 0:
                return op(f"c.q[{rd}] = rt::Vec{{c.q[{rn}].lo & {lo_mask}, 0}};")
            if kind == 1:
                return op(f"c.q[{rd}] = rt::Vec{{c.q[{rn}].lo & {lo_mask} & ~{sign}, 0}};")
            if kind == 2:
                return op(f"c.q[{rd}] = rt::Vec{{(c.q[{rn}].lo & {lo_mask}) ^ {sign}, 0}};")
            return op(put(f"rt::Fsqrt({get(rn)})"))
        if m(0xFF3E7C00, 0x1E224000) and bits(w, 16, 15) != ftype and bits(w, 16, 15) in (0, 1):  # FCVT
            to = bits(w, 16, 15)
            return op(f"c.q[{rd}] = rt::FromFp({'float' if to == 0 else 'double'}({get(rn)}));")
        if m(0xFF3C7C00, 0x1E244000):  # FRINT[NPMZAXI]
            r = bits(w, 17, 15)
            mode = {0: "N", 1: "P", 2: "M", 3: "Z", 4: "A", 6: "N", 7: "N"}.get(r)
            if mode is None:
                return None
            return op(put(f"rt::Frint({get(rn)}, rt::Round::{mode})"))
        if m(0xFF200C00, 0x1E200800):  # two sources
            fn = {0: "Fmul", 1: "Fdiv", 2: "Fadd", 3: "Fsub", 4: "Fmax", 5: "Fmin", 6: "Fmaxnm", 7: "Fminnm"}
            opcode = bits(w, 15, 12)
            if opcode == 8:
                return op(put(f"rt::Neg(rt::Fmul({get(rn)}, {get(rm)}))"))
            if opcode not in fn:
                return None
            return op(put(f"rt::{fn[opcode]}({get(rn)}, {get(rm)})"))
        if m(0xFF20FC07, 0x1E202000):  # FCMP, FCMPE
            other = f"{ty}(0)" if bits(w, 3, 3) else get(rm)
            return op(f"rt::Fcmp<{ty}>(c, {get(rn)}, {other});")
        if m(0xFF200C00, 0x1E200400):  # FCCMP, FCCMPE
            cond, nzcv = CONDS[bits(w, 15, 12)], w & 15
            return op(f"if ({cond}) rt::Fcmp<{ty}>(c, {get(rn)}, {get(rm)}); else rt::SetNzcv(c, {nzcv});")
        if m(0xFF200C00, 0x1E200C00):  # FCSEL
            cond = CONDS[bits(w, 15, 12)]
            return op(f"c.q[{rd}] = rt::Vec{{(({cond}) ? c.q[{rn}].lo : c.q[{rm}].lo) & {lo_mask}, 0}};")
        if m(0xFF201FE0, 0x1E201000):  # FMOV (immediate)
            imm8 = bits(w, 20, 13)
            value = vfp_expand_imm64(imm8) if ftype else vfp_expand_imm32(imm8)
            return op(f"c.q[{rd}] = rt::Vec{{0x{value:x}ull, 0}};")
        return None

    def scalar_simd_fp(self, w, rd, rn, rm):
        """Scalar forms in the Advanced SIMD encoding space."""
        def m(mask, val):
            return w & mask == val

        if m(0xDFBFFC00, 0x5EA1D800):  # FRECPE, FRSQRTE (scalar)
            ty = "double" if bits(w, 22, 22) else "float"
            get = "rt::D" if bits(w, 22, 22) else "rt::F"
            fn = "Frsqrte" if bits(w, 29, 29) else "Frecpe"
            return Insn("op", [f"c.q[{rd}] = rt::FromFp(rt::{fn}<{ty}>({get}(c.q[{rn}])));"])
        if m(0xFF20FC00, 0x5E20FC00):  # FRECPS, FRSQRTS (scalar)
            ty = "double" if bits(w, 22, 22) else "float"
            get = "rt::D" if bits(w, 22, 22) else "rt::F"
            fn = "Frsqrts" if bits(w, 23, 23) else "Frecps"
            return Insn("op", [f"c.q[{rd}] = rt::FromFp(rt::{fn}<{ty}>({get}(c.q[{rn}]), {get}(c.q[{rm}])));"])
        if m(0xFFE0CC00, 0x5E000000):  # SHA1C, SHA1P, SHA1M, SHA1SU0
            kind = bits(w, 13, 12)
            if kind == 3:
                return Insn("op", [f"c.q[{rd}] = rt::Sha1Su0(c.q[{rd}], c.q[{rn}], c.q[{rm}]);"])
            return Insn("op", [f"c.q[{rd}] = rt::Sha1Hash(c.q[{rd}], u32(c.q[{rn}].lo), c.q[{rm}], {kind});"])
        if m(0xFFFFFC00, 0x5E280800):  # SHA1H
            return Insn("op", [f"c.q[{rd}] = rt::Sha1H(c.q[{rn}]);"])
        if m(0xFFFFFC00, 0x5E281800):  # SHA1SU1
            return Insn("op", [f"c.q[{rd}] = rt::Sha1Su1(c.q[{rd}], c.q[{rn}]);"])
        if m(0xFFBFFC00, 0x7E30D800):  # FADDP (scalar)
            return Insn("op", [f"c.q[{rd}] = rt::Faddp(c.q[{rn}], {2 + bits(w, 22, 22)});"])

        if m(0xDFBFFC00, 0x5E21D800):  # SCVTF, UCVTF (scalar, integer in a vector register)
            sz, unsigned = bits(w, 22, 22), bits(w, 29, 29)
            ty = "double" if sz else "float"
            it = ("u64" if sz else "u32") if unsigned else ("s64" if sz else "s32")
            return Insn("op", [f"c.q[{rd}] = rt::FromFp(rt::IntToFp<{ty}>({it}(c.q[{rn}].lo)));"])
        if m(0xFF80F400, 0x5F809000):  # FMUL (scalar, by element)
            sz, L, H = bits(w, 22, 22), bits(w, 21, 21), bits(w, 11, 11)
            if sz and L:
                return None
            index = (H << 1 | L) if not sz else H  # Rm includes M for 32- and 64-bit elements
            if sz:
                return Insn("op", [f"c.q[{rd}] = rt::FromD(rt::Fmul(rt::D(c.q[{rn}]), "
                                   f"std::bit_cast<double>(rt::VLane(c.q[{rm}], 3, {index}))));"])
            return Insn("op", [f"c.q[{rd}] = rt::FromF(rt::Fmul(rt::F(c.q[{rn}]), "
                               f"std::bit_cast<float>(u32(rt::VLane(c.q[{rm}], 2, {index})))));"])
        if m(0xFFE0FC00, 0x5E000400):  # DUP (element, scalar): MOV Vd, Vn.T[i]
            imm5 = bits(w, 20, 16)
            if imm5 & 15 == 0:
                return None
            size = (imm5 & -imm5).bit_length() - 1
            return Insn("op", [f"c.q[{rd}] = rt::VElem(c.q[{rn}], {size}, {imm5 >> (size + 1)});"])
        return None

    def neon(self, w, rd, rn, rm, q):
        """Advanced SIMD vector forms beyond the ones in simd()."""
        def m(mask, val):
            return w & mask == val

        vq, vn, vm = f"c.q[{rd}]", f"c.q[{rn}]", f"c.q[{rm}]"
        op = lambda code: Insn("op", [code])
        size = bits(w, 23, 22)

        if m(0xBF80F400, 0x0F809000):  # FMUL (vector, by element)
            sz, L, H = bits(w, 22, 22), bits(w, 21, 21), bits(w, 11, 11)
            if sz and (L or not q):
                return None
            index = (H << 1 | L) if not sz else H
            return op(f"{vq} = rt::VFmul({vn}, {vm}, {2 + sz}, {q}, {index});")
        if m(0xBFA0FC00, 0x2E20DC00):  # FMUL (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            return op(f"{vq} = rt::VFmul({vn}, {vm}, {2 + sz}, {q});")
        if m(0xBFA0FC00, 0x0E20D400) or m(0xBFA0FC00, 0x0EA0D400):  # FADD, FSUB (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            fn = "VFsub" if bits(w, 23, 23) else "VFadd"
            return op(f"{vq} = rt::{fn}({vn}, {vm}, {2 + sz}, {q});")
        if m(0x9FF80C00, 0x0F000400) and not (bits(w, 29, 29) and bits(w, 15, 12) == 0b1110):  # modified immediate
            value = advsimd_expand_imm(bits(w, 29, 29), bits(w, 15, 12), bits(w, 18, 16) << 5 | bits(w, 9, 5))
            if value is None:
                return None
            kind, imm = value
            hi = imm if q else 0
            if kind == "set":
                return op(f"{vq} = rt::Vec{{0x{imm:x}ull, 0x{hi:x}ull}};")
            if kind == "orr":
                return op(f"{vq} = rt::Vec{{{vq}.lo | 0x{imm:x}ull, {'(' + vq + '.hi | 0x' + format(imm, 'x') + 'ull)' if q else '0'}}};")
            return op(f"{vq} = rt::Vec{{{vq}.lo & ~0x{imm:x}ull, {'(' + vq + '.hi & ~0x' + format(imm, 'x') + 'ull)' if q else '0'}}};")
        if m(0xBFE0FC00, 0x0E000400):  # DUP (element)
            imm5 = bits(w, 20, 16)
            if imm5 & 15 == 0:
                return None
            s = (imm5 & -imm5).bit_length() - 1
            return op(f"{vq} = rt::VDupElem({vn}, {s}, {imm5 >> (s + 1)}, {q});")
        if m(0xFFE0FC00, 0x4E001C00):  # INS (general): MOV Vd.T[i], Rn
            imm5 = bits(w, 20, 16)
            if imm5 & 15 == 0:
                return None
            s = (imm5 & -imm5).bit_length() - 1
            return op(f"{vq} = rt::VIns({vq}, {s}, {imm5 >> (s + 1)}, {rs(rn, 1)});")
        if m(0xFFE08400, 0x6E000400):  # INS (element): MOV Vd.T[i], Vn.T[j]
            imm5, imm4 = bits(w, 20, 16), bits(w, 14, 11)
            if imm5 & 15 == 0:
                return None
            s = (imm5 & -imm5).bit_length() - 1
            return op(f"{vq} = rt::VIns({vq}, {s}, {imm5 >> (s + 1)}, rt::VLane({vn}, {s}, {imm4 >> s}));")
        if m(0x9F80FC00, 0x0F00A400) and bits(w, 22, 19):  # SSHLL, USHLL (SXTL, UXTL)
            immh = bits(w, 22, 19)
            s = immh.bit_length() - 1
            if s > 2:
                return None
            shift = bits(w, 22, 16) - (8 << s)
            unsigned = "false" if bits(w, 29, 29) else "true"
            return op(f"{vq} = rt::VShll({vn}, {s}, {shift}, {'true' if q else 'false'}, {unsigned});")
        if m(0xBF3FFC00, 0x0E212800):  # XTN, XTN2
            if size == 3:
                return None
            return op(f"{vq} = rt::VXtn({vq}, {vn}, {size}, {'true' if q else 'false'});")
        if m(0xBF208C00, 0x0E000800):  # UZP, TRN, ZIP
            opcode = bits(w, 14, 12)
            if size == 3 and not q:
                return None
            fn = {1: ("VUzp", 0), 2: ("VTrn", 0), 3: ("VZip", 0), 5: ("VUzp", 1), 6: ("VTrn", 1), 7: ("VZip", 1)}.get(opcode)
            if not fn:
                return None
            return op(f"{vq} = rt::{fn[0]}({vn}, {vm}, {size}, {q}, {fn[1]});")
        if m(0xBFE08C00, 0x0E000000):  # TBL, TBX
            count = bits(w, 14, 13) + 1
            ext = "true" if bits(w, 12, 12) else "false"
            return op(f"{vq} = rt::VTbl(c, {vq}, {rn}, {count}, {vm}, {q}, {ext});")
        if m(0x9F20F400, 0x0E206400):  # SMAX, SMIN, UMAX, UMIN
            if size == 3:
                return None
            unsigned, is_min = bits(w, 29, 29), bits(w, 11, 11)
            return op(f"{vq} = rt::VMinMax({vn}, {vm}, {size}, {q}, {'false' if unsigned else 'true'}, "
                      f"{'false' if is_min else 'true'});")
        if m(0xBFFFFC00, 0x0E205800):  # CNT
            return op(f"{vq} = rt::VCnt({vn}, {q});")
        if m(0xBFE0FC00, 0x0EE0E000):  # PMULL, PMULL2 (64-bit lanes)
            half = "hi" if q else "lo"
            return op(f"{vq} = rt::Pmull64({vn}.{half}, {vm}.{half});")
        if m(0xBF80B400, 0x0F801000):  # FMLA, FMLS (vector, by element)
            sz, L, H = bits(w, 22, 22), bits(w, 21, 21), bits(w, 11, 11)
            if sz and (L or not q):
                return None
            index = (H << 1 | L) if not sz else H
            sub = "true" if bits(w, 14, 14) else "false"
            return op(f"{vq} = rt::VFmla({vq}, {vn}, {vm}, {2 + sz}, {q}, {index}, {sub});")
        if m(0xBF20FC00, 0x0E20CC00):  # FMLA, FMLS (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            sub = "true" if bits(w, 23, 23) else "false"
            return op(f"{vq} = rt::VFmla({vq}, {vn}, {vm}, {2 + sz}, {q}, -1, {sub});")
        if m(0xBFE08400, 0x2E000000):  # EXT
            index = bits(w, 14, 11)
            if not q and index > 7:
                return None
            return op(f"{vq} = rt::VExt({vn}, {vm}, {index}, {q});")
        zero_cmp = {(0, 0): "Gt", (1, 0): "Ge", (0, 1): "Eq", (1, 1): "Le", (0, 2): "Lt"}
        if m(0x9FBFCC00, 0x0EA0C800) and (bits(w, 29, 29), bits(w, 13, 12)) in zero_cmp:  # FCMxx (zero)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            cmp = zero_cmp[(bits(w, 29, 29), bits(w, 13, 12))]
            return op(f"{vq} = rt::VFcm({vn}, rt::Vec{{0, 0}}, {2 + sz}, {q}, rt::FpCompare::{cmp});")
        if m(0x9F20FC00, 0x0E20E400):  # FCMEQ, FCMGE, FCMGT (register)
            sz, u, e = bits(w, 22, 22), bits(w, 29, 29), bits(w, 23, 23)
            if sz and not q:
                return None
            cmp = {(0, 0): "Eq", (1, 0): "Ge", (1, 1): "Gt"}.get((u, e))
            if not cmp:
                return None
            return op(f"{vq} = rt::VFcm({vn}, {vm}, {2 + sz}, {q}, rt::FpCompare::{cmp});")
        if m(0x9F3EFC00, 0x0E30A800):  # SMAXV, SMINV (UMAXV, UMINV are in simd())
            if bits(w, 29, 29) or size == 3:
                return None
            return op(f"{vq} = rt::VSmaxv({vn}, {size}, {q}, {'false' if bits(w, 16, 16) else 'true'});")
        if m(0x9F3FFC00, 0x0E303800):  # SADDLV, UADDLV
            if size == 3:
                return None
            return op(f"{vq} = rt::VAddlv({vn}, {size}, {q}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0xBF20FC00, 0x0E209C00):  # MUL (vector)
            if size == 3:
                return None
            return op(f"{vq} = rt::VMul({vn}, {vm}, {size}, {q});")
        if m(0xBF80FC00, 0x0F005400) and bits(w, 22, 19):  # SHL
            immh = bits(w, 22, 19)
            esize = immh.bit_length() - 1
            if esize == 3 and not q:
                return None
            return op(f"{vq} = rt::VShl({vn}, {esize}, {bits(w, 22, 16) - (8 << esize)}, {q});")
        if m(0xBF20FC00, 0x2E201C00) or m(0xBF20FC00, 0x0E201C00):  # EOR, BIC, ORN, BSL, BIT (AND, ORR, BIF in simd())
            u, opc = bits(w, 29, 29), bits(w, 23, 22)
            hi = lambda e: e if q else "0"
            if not u and opc == 1:  # BIC
                return op(f"{vq} = rt::Vec{{{vn}.lo & ~{vm}.lo, {hi(f'({vn}.hi & ~{vm}.hi)')}}};")
            if not u and opc == 3:  # ORN
                return op(f"{vq} = rt::Vec{{{vn}.lo | ~{vm}.lo, {hi(f'({vn}.hi | ~{vm}.hi)')}}};")
            if u and opc == 0:  # EOR
                return op(f"{vq} = rt::Vec{{{vn}.lo ^ {vm}.lo, {hi(f'({vn}.hi ^ {vm}.hi)')}}};")
            if u and opc == 1:  # BSL: d selects n where set, m where clear
                return op(f"{vq} = rt::Vec{{({vq}.lo & {vn}.lo) | (~{vq}.lo & {vm}.lo), "
                          f"{hi(f'(({vq}.hi & {vn}.hi) | (~{vq}.hi & {vm}.hi))')}}};")
            if u and opc == 2:  # BIT: n where m is set
                return op(f"{vq} = rt::Vec{{({vq}.lo & ~{vm}.lo) | ({vn}.lo & {vm}.lo), "
                          f"{hi(f'(({vq}.hi & ~{vm}.hi) | ({vn}.hi & {vm}.hi))')}}};")
            return None
        if m(0x9F20F400, 0x0E203400) or m(0xBF20FC00, 0x0E208C00):  # CMGT, CMGE, CMHI, CMHS, CMTST
            if size == 3 and not q:
                return None
            if m(0xBF20FC00, 0x0E208C00):
                cmp = "Tst"
            else:
                cmp = {(0, 0): "Gt", (0, 1): "Ge", (1, 0): "Hi", (1, 1): "Hs"}[(bits(w, 29, 29), bits(w, 11, 11))]
            return op(f"{vq} = rt::VCm({vn}, {vm}, {size}, {q}, rt::IntCompare::{cmp});")
        if m(0x9F3FFC00, 0x0E20B800):  # ABS, NEG (vector)
            if size == 3 and not q:
                return None
            return op(f"{vq} = rt::VNegAbs({vn}, {size}, {q}, {'true' if bits(w, 29, 29) else 'false'});")
        if m(0x9FBFFC00, 0x0EA1D800):  # FRECPE, FRSQRTE (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            fn = "VFrsqrte" if bits(w, 29, 29) else "VFrecpe"
            return op(f"{vq} = rt::{fn}({vn}, {2 + sz}, {q});")
        if m(0xBF20FC00, 0x0E20FC00):  # FRECPS, FRSQRTS (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            fn = "VFrsqrts" if bits(w, 23, 23) else "VFrecps"
            return op(f"{vq} = rt::{fn}({vn}, {vm}, {2 + sz}, {q});")
        if m(0x9FBFFC00, 0x0EA0F800):  # FABS, FNEG (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            fn = "VFneg" if bits(w, 29, 29) else "VFabs"
            return op(f"{vq} = rt::{fn}({vn}, {2 + sz}, {q});")
        if m(0x9F80FC00, 0x0F000400) and bits(w, 22, 19):  # SSHR, USHR
            immh = bits(w, 22, 19)
            esize = immh.bit_length() - 1
            if esize == 3 and not q:
                return None
            shift = (16 << esize) - bits(w, 22, 16)
            return op(f"{vq} = rt::VShr({vn}, {esize}, {shift}, {q}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0xBF3FFC00, 0x0E31B800):  # ADDV
            if size == 3 or (size == 2 and not q):
                return None
            return op(f"{vq} = rt::VAddv({vn}, {size}, {q});")
        if m(0x9F20FC00, 0x0E20C000) or m(0x9F20FC00, 0x0E208000) or m(0x9F20FC00, 0x0E20A000):
            # SMULL, UMULL, SMLAL, UMLAL, SMLSL, UMLSL (and the "2" forms)
            if size == 3:
                return None
            acc = {0b1100: 0, 0b1000: 1, 0b1010: 2}[bits(w, 15, 12)]
            return op(f"{vq} = rt::VMull({vq}, {vn}, {vm}, {size}, {'true' if q else 'false'}, "
                      f"{'false' if bits(w, 29, 29) else 'true'}, {acc});")
        zero_int = {(0, 0): ("Gt", False), (1, 0): ("Ge", False), (0, 1): ("Eq", False), (1, 1): ("Ge", True),
                    (0, 2): ("Gt", True)}
        if m(0x9F3FCC00, 0x0E208800) and (bits(w, 29, 29), bits(w, 13, 12)) in zero_int:  # CMxx (zero)
            if size == 3 and not q:
                return None
            cmp, swap = zero_int[(bits(w, 29, 29), bits(w, 13, 12))]  # LE and LT compare 0 against n
            a, b = ("rt::Vec{0, 0}", vn) if swap else (vn, "rt::Vec{0, 0}")
            return op(f"{vq} = rt::Narrow(rt::VCm({a}, {b}, {size}, {q}, rt::IntCompare::{cmp}), {q});")
        if m(0x9F20DC00, 0x0E200C00):  # SQADD, UQADD, SQSUB, UQSUB
            if size == 3 and not q:
                return None
            return op(f"{vq} = rt::VQAddSub({vn}, {vm}, {size}, {q}, {'false' if bits(w, 29, 29) else 'true'}, "
                      f"{'true' if bits(w, 13, 13) else 'false'});")
        if (m(0x9F00F400, 0x0F002000) or m(0x9F00F400, 0x0F006000) or m(0x9F00F400, 0x0F00A000)) and size in (1, 2):
            # SMLAL, UMLAL, SMLSL, UMLSL, SMULL, UMULL (by element)
            L_, M_, H = bits(w, 21, 21), bits(w, 20, 20), bits(w, 11, 11)
            index, reg = (H << 2 | L_ << 1 | M_, rm & 15) if size == 1 else (H << 1 | L_, rm)
            acc = {0b0010: 1, 0b0110: 2, 0b1010: 0}[bits(w, 15, 12)]
            return op(f"{vq} = rt::VMull({vq}, {vn}, c.q[{reg}], {size}, {'true' if q else 'false'}, "
                      f"{'false' if bits(w, 29, 29) else 'true'}, {acc}, {index});")
        if m(0x9F80F400, 0x0F009400) and bits(w, 22, 19):  # SQSHRN, SQRSHRN, UQSHRN, UQRSHRN
            immh = bits(w, 22, 19)
            dsize = immh.bit_length() - 1
            if dsize > 2:
                return None
            shift = (16 << dsize) - bits(w, 22, 16)
            return op(f"{vq} = rt::VQShrn({vq}, {vn}, {dsize}, {shift}, {'true' if q else 'false'}, "
                      f"{'true' if bits(w, 11, 11) else 'false'}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0xFFFFCC00, 0x4E284800):  # AESE, AESD, AESMC, AESIMC
            kind = bits(w, 13, 12)
            if kind < 2:
                return op(f"{vq} = rt::Aese({vq}, {vn}, {'true' if kind else 'false'});")
            return op(f"{vq} = rt::Aesmc({vn}, {'true' if kind == 3 else 'false'});")
        if m(0xBFA0FC00, 0x2E20D400):  # FADDP (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            return op(f"{vq} = rt::VFaddp({vn}, {vm}, {2 + sz}, {q});")
        if m(0x9FBFFC00, 0x0E21D800):  # SCVTF, UCVTF (vector, integer)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            return op(f"{vq} = rt::VIntToFp({vn}, {2 + sz}, {q}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0x9FBFFC00, 0x0EA1B800):  # FCVTZS, FCVTZU (vector)
            sz = bits(w, 22, 22)
            if sz and not q:
                return None
            return op(f"{vq} = rt::VFcvtz({vn}, {2 + sz}, {q}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0xBF00F400, 0x0F008000) and size in (1, 2):  # MUL (by element)
            L, M_, H = bits(w, 21, 21), bits(w, 20, 20), bits(w, 11, 11)
            if size == 1:
                index, reg = H << 2 | L << 1 | M_, rm & 15
            else:
                index, reg = H << 1 | L, rm
            return op(f"{vq} = rt::VMul({vn}, c.q[{reg}], {size}, {q}, {index});")
        if m(0x9F20FC00, 0x0E204400):  # SSHL, USHL
            if size == 3 and not q:
                return None
            return op(f"{vq} = rt::VShlReg({vn}, {vm}, {size}, {q}, {'false' if bits(w, 29, 29) else 'true'});")
        if m(0xBF20FC00, 0x2E208400):  # SUB (vector)
            if size == 3 and not q:
                return None
            return op(f"{vq} = rt::VSub({vn}, {vm}, {size}, {q});")
        if m(0xBF3FEC00, 0x0E200800):  # REV64, REV16
            container = 2 if bits(w, 12, 12) else 8
            if size >= container.bit_length() - 1:
                return None
            return op(f"{vq} = rt::VRev({vn}, {size}, {container}, {q});")
        return None


# Module image and function discovery --------------------------------------


class Image:
    def __init__(self, path):
        data = Path(path).read_bytes()
        if data[:4] != b"\x7fELF":
            raise SystemExit(f"{path}: not an ELF")
        self.entry = struct.unpack_from("<Q", data, 0x18)[0]
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        self.segments = []
        for i in range(phnum):
            ptype, flags, off, va, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56)
            if ptype == 1:
                self.segments.append((va, data[off:off + filesz], memsz, flags))
        text = [s for s in self.segments if s[3] & 1]
        if len(text) != 1:
            raise SystemExit("expected exactly one executable segment")
        self.text_base, self.text, _, _ = text[0]
        self.text_end = self.text_base + len(self.text)
        if not self.entry:
            self.entry = self.text_base

    def text_ranges(self):
        return [(self.text_base, self.text_end)]

    def dynamic(self):
        """The module's dynamic section as {tag: value}, found through MOD0;
        values that are addresses are offsets from the module base."""
        base = self.text_base
        raw = self.read(base + 4, 4)
        if raw is None:
            return {}
        mod0 = base + struct.unpack("<I", raw)[0]
        if self.read(mod0, 4) != b"MOD0":
            return {}
        at = mod0 + struct.unpack("<i", self.read(mod0 + 4, 4))[0]
        tags = {}
        while True:
            entry = self.read(at, 16)
            if entry is None:
                break
            tag, value = struct.unpack("<QQ", entry)
            if tag == 0:
                break
            tags.setdefault(tag, value)
            at += 16
        return tags

    def dynamic_entries(self):
        """DT_INIT and DT_FINI: functions the module's startup code calls by
        offset from the module base, so no pointer to them exists. Also where
        each lazily bound GOT slot starts out (the PLT's resolver stub): those
        slots hold offsets until the module relocates itself."""
        base, tags = self.text_base, self.dynamic()
        found = {base + v for t, v in tags.items() if t in (12, 13) and self.in_text(base + v)}
        if 23 in tags and 2 in tags:  # DT_JMPREL, DT_PLTRELSZ
            for at in range(base + tags[23], base + tags[23] + tags[2], 24):
                raw = self.read(at, 24)
                if raw is None:
                    break
                offset, info, _ = struct.unpack("<QQq", raw)
                slot = self.read(base + offset, 8)
                if info & 0xFFFFFFFF == 1026 and slot:  # R_AARCH64_JUMP_SLOT
                    target = base + struct.unpack("<Q", slot)[0]
                    if self.in_text(target):
                        found.add(target)
        return found

    def exported_functions(self):
        """Functions the module defines in its dynamic symbol table. Another
        module reaches them only through a GOT slot rtld fills at run time,
        so they are entry points even with no pointer to them here."""
        base, tags = self.text_base, self.dynamic()
        if 6 not in tags:  # DT_SYMTAB
            return set()
        symtab, entsize = base + tags[6], tags.get(11, 24)
        count = 0
        if 4 in tags:  # DT_HASH: nchain is the symbol count
            raw = self.read(base + tags[4] + 4, 4)
            count = struct.unpack("<I", raw)[0] if raw else 0
        elif 0x6FFFFEF5 in tags:  # DT_GNU_HASH: the last chain of the highest bucket
            gnu = base + tags[0x6FFFFEF5]
            head = self.read(gnu, 16)
            if head:
                nbuckets, symoffset, bloom_size, _ = struct.unpack("<IIII", head)
                buckets_at = gnu + 16 + bloom_size * 8
                raw = self.read(buckets_at, nbuckets * 4) or b""
                buckets = struct.unpack(f"<{len(raw) // 4}I", raw)
                last = max(buckets, default=0)
                if last >= symoffset:
                    chains_at = buckets_at + nbuckets * 4
                    while True:
                        h = self.read(chains_at + (last - symoffset) * 4, 4)
                        if h is None or struct.unpack("<I", h)[0] & 1:
                            break
                        last += 1
                    count = last + 1
                else:
                    count = symoffset
        elif 5 in tags and tags[5] > tags[6]:  # DT_STRTAB right after the symbols
            count = (tags[5] - tags[6]) // entsize
        found = set()
        for i in range(count):
            raw = self.read(symtab + i * entsize, 24)
            if raw is None:
                break
            _, info, _, shndx, value, _ = struct.unpack("<IBBHQQ", raw)
            if info & 0xF == 2 and shndx != 0 and self.in_text(base + value):  # STT_FUNC, defined
                found.add(base + value)
        return found

    def in_text(self, addr):
        return self.text_base <= addr < self.text_end and addr % 4 == 0

    def word(self, addr):
        return struct.unpack_from("<I", self.text, addr - self.text_base)[0]

    def read(self, addr, size):
        for va, blob, _, _ in self.segments:
            if va <= addr and addr + size <= va + len(blob):
                return blob[addr - va:addr - va + size]
        return None


class Program:
    """Several modules loaded together, as the ExeFS's modules are: one
    address space, entered at the first module (rtld)."""

    def __init__(self, images):
        self.images = images
        self.entry = images[0].entry
        self.segments = [seg for img in images for seg in img.segments]
        for a, b in zip(images, images[1:]):
            if a.segments[-1][0] + a.segments[-1][2] > b.text_base:
                raise SystemExit("modules overlap: lay them out with nso.py --exefs")

    def text_ranges(self):
        return [r for img in self.images for r in img.text_ranges()]

    def module_of(self, addr):
        for img in self.images:
            if img.text_base <= addr < img.text_end:
                return img
        return None

    def in_text(self, addr):
        img = self.module_of(addr)
        return img is not None and addr % 4 == 0

    def word(self, addr):
        return self.module_of(addr).word(addr)

    def read(self, addr, size):
        for img in self.images:
            got = img.read(addr, size)
            if got is not None:
                return got
        return None

    def dynamic_entries(self):
        return set().union(*(img.dynamic_entries() for img in self.images))

    def exported_functions(self):
        return set().union(*(img.exported_functions() for img in self.images))


class Lifter:
    def __init__(self, image):
        self.image = image
        self.decoder = Decoder(image)
        self.cache = {}
        self.unresolved_br = []
        self.traps = Counter()
        self.track_pc = False

    def insn(self, pc):
        if pc not in self.cache:
            i = self.decoder.decode(pc, self.image.word(pc))
            if i.kind == "bl" and i.target == pc + 8:
                # A bl over a data word only takes the word's address in x30
                # (rtld's position-independent idiom); it does not return here.
                i = Insn("b", [f"c.x[30] = 0x{pc + 4:x}ull;"], target=pc + 8)
            n = stack_switch(self.image, pc)
            if n is not None:
                # Another context's stack: the runtime switches host fibers,
                # and a new context starts at the next instruction.
                i = Insn("op", [f"{{ const u64 previous = c.sp; c.sp = c.x[{n}]; "
                                f"rt::SwitchStack(c, previous, 0x{pc + 4:x}ull); }}"])
            self.cache[pc] = i
        return self.cache[pc]

    def entries(self):
        """Entry points: the module entry, every BL target, code addresses
        built by ADR/ADRP+ADD, code addresses stored in data, DT_INIT and
        DT_FINI, and exported functions."""
        img = self.image
        found = {img.entry}
        for pc in (pc for base, end in img.text_ranges() for pc in range(base, end, 4)):
            w = img.word(pc)
            if w & 0xFC000000 == 0x94000000:
                t = (pc + (sext(w & 0x3FFFFFF, 26) << 2)) & M64
                if img.in_text(t):
                    found.add(t)
                # rtld's position-independent idiom: bl over a 32-bit offset,
                # then ldr wN, [x30] and add it to x30.
                if t == pc + 8 and img.word(pc + 8) & 0xFFFFFFE0 == 0xB94003C0:
                    t = (pc + 4 + sext(img.word(pc + 4), 32)) & M64
                    if img.in_text(t):
                        found.add(t)
            elif w & 0x9F000000 == 0x10000000:  # adr
                t = (pc + sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21)) & M64
                if img.in_text(t):
                    found.add(t)
            elif w & 0x9F000000 == 0x90000000:  # adrp, then an add from it (often scheduled later)
                page = (pc & ~0xFFF) + (sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21) << 12)
                rd = w & 31
                for k in range(1, 9):
                    if not img.in_text(pc + 4 * k):
                        break
                    nxt = img.word(pc + 4 * k)
                    if nxt & 0xFFC00000 == 0x91000000 and bits(nxt, 9, 5) == rd:
                        t = (page + bits(nxt, 21, 10)) & M64
                        if img.in_text(t):
                            found.add(t)
                    if nxt & 31 == rd and not is_store(nxt):
                        break
            elif stack_switch(img, pc) is not None:
                found.add(pc + 4)  # where a new context starts
        found.update(img.dynamic_entries())
        found.update(img.exported_functions())
        for va, blob, _, flags in img.segments:
            if flags & 1:
                continue
            for off in range(0, len(blob) - 7, 8):
                t = struct.unpack_from("<Q", blob, off)[0]
                if img.in_text(t):
                    found.add(t)
        return found

    def jump_table(self, pc, reg):
        """Recognise adr xB, L; ldr{b,h} wO, [xT, xI{, lsl}]; add xB, xB, xO, lsl #2; br xB,
        or a table of 32-bit offsets from its own start: ldrsw xO, [xT, xI, lsl #2];
        add xB, xO, xT; br xB.

        Returns the list of targets, or None.
        """
        targets = self.jump_table_rel32(pc, reg)
        if targets:
            return targets
        img = self.image
        window = [pc - 4 * i for i in range(1, 13)]
        add = ldr = adr = None
        for a in window:
            if not img.in_text(a):
                break
            w = img.word(a)
            if add is None and w & 0xFFE00000 == 0x8B000000 and (w & 31) == reg:
                add = (a, w)
            elif add is not None and ldr is None and bits(w, 31, 30) in (0, 1) and w & 0x3FE00C00 == 0x38600800 \
                    and (w & 31) == bits(add[1], 20, 16):
                ldr = (a, w)
            elif adr is None and add is not None and w & 0x9F000000 == 0x10000000 and (w & 31) == bits(add[1], 9, 5):
                adr = (a, w)
        if not (add and ldr and adr):
            return None
        base = (adr[0] + sext(bits(adr[1], 23, 5) << 2 | bits(adr[1], 30, 29), 21)) & M64
        shift = bits(add[1], 15, 10)
        if bits(add[1], 23, 22) != 0:
            return None
        entry_size = 1 << bits(ldr[1], 31, 30)
        table_reg, index_reg = bits(ldr[1], 9, 5), bits(ldr[1], 20, 16)
        table = self.find_constant(ldr[0], table_reg)
        count = self.find_bound(ldr[0], index_reg)
        if table is None or count is None:
            return None
        raw = img.read(table, count * entry_size)
        if raw is None:
            return None
        fmt = "<%d%s" % (count, "B" if entry_size == 1 else "H")
        return sorted({(base + (e << shift)) & M64 for e in struct.unpack(fmt, raw)})

    def jump_table_rel32(self, pc, reg):
        img = self.image
        add = ldr = None
        for a in (pc - 4 * i for i in range(1, 8)):
            if not img.in_text(a):
                return None
            w = img.word(a)
            if add is None:
                # add xB, xN, xM with no shift
                if w & 0xFFE0FC00 == 0x8B000000 and w & 31 == reg:
                    add = w
                elif w & 31 == reg and not is_store(w):
                    return None
            elif w & 0xFFE0FC00 == 0xB8A07800:  # ldrsw xT, [xN, xM, lsl #2]
                t, base_reg, index_reg = w & 31, bits(w, 9, 5), bits(w, 20, 16)
                if sorted((t, base_reg)) == sorted((bits(add, 9, 5), bits(add, 20, 16))):
                    ldr = (a, base_reg, index_reg)
                break
        if not ldr:
            return None
        table = self.find_constant(ldr[0], ldr[1])
        if table is None:
            return None
        count = self.find_bound(ldr[0], ldr[2])
        if count is None:
            # Reached from a guard elsewhere: take entries while they stay near
            # the branch. A case too many only adds an unused label.
            targets = []
            while len(targets) < 1024:
                raw = img.read(table + 4 * len(targets), 4)
                t = (table + struct.unpack("<i", raw)[0]) & M64 if raw else None
                if t is None or t % 4 or abs(t - pc) > 0x8000 or not img.in_text(t):
                    break
                targets.append(t)
            return sorted(set(targets)) or None
        raw = img.read(table, count * 4)
        if raw is None:
            return None
        return sorted({(table + e) & M64 for e in struct.unpack("<%di" % count, raw)})

    def find_constant(self, pc, reg):
        """Value of reg at pc if set by adr, or adrp+add, within this function's linear prefix
        (following a register move)."""
        img = self.image
        a = pc - 4
        for _ in range(1024):
            if not img.in_text(a):
                return None
            w = img.word(a)
            if w & 0xFFE0FFE0 == 0xAA0003E0 and w & 31 == reg:  # mov reg, xM
                reg = bits(w, 20, 16)
                a -= 4
                continue
            if w & 0x9F000000 == 0x10000000 and w & 31 == reg:
                return (a + sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21)) & M64
            if w & 0xFFC00000 == 0x91000000 and w & 31 == reg and bits(w, 9, 5) == reg:
                # The adrp is often scheduled well before its add.
                b = a - 4
                for _ in range(64):
                    if not img.in_text(b):
                        return None
                    p = img.word(b)
                    if p & 0x9F000000 == 0x90000000 and p & 31 == reg:
                        page = (b & ~0xFFF) + (sext(bits(p, 23, 5) << 2 | bits(p, 30, 29), 21) << 12)
                        return (page + bits(w, 21, 10)) & M64
                    if p & 31 == reg and not is_store(p) or p & 0xFFFFFC1F == 0xD65F0000:
                        return None
                    b -= 4
                return None
            if w & 0xFFFFFC1F == 0xD65F0000:  # ret: left the function
                return None
            a -= 4
        return None

    def find_bound(self, pc, reg):
        """Entry count from the guard before a jump table: the nearest b.hi or
        b.hs, and the nearest earlier cmp of the index register (following
        register moves). The compiler sometimes schedules other instructions
        between them, or reaches the table from a second guard."""
        img = self.image
        a = pc - 4
        extra = None
        for _ in range(8):
            if not img.in_text(a):
                return None
            w = img.word(a)
            if w & 0xFF00001F == 0x54000008:
                extra = 1
                break
            if w & 0xFF00001F == 0x54000002:
                extra = 0
                break
            a -= 4
        if extra is None:
            return None
        window = []
        a = pc - 4
        for _ in range(64):
            if not img.in_text(a):
                break
            w = img.word(a)
            if w & 0xFFFFFC1F == 0xD65F0000:
                break
            window.append(w)
            a -= 4
        regs = {reg}
        for _ in range(4):  # copies may appear on either side of the cmp
            for w in window:
                if w & 0x7FE0FFE0 == 0x2A0003E0 and w & 31 in regs:  # mov rd, rm
                    regs.add(bits(w, 20, 16))
        for w in window:
            if w & 0x7FC0001F == 0x7100001F and bits(w, 9, 5) in regs:  # cmp rn, #imm
                return bits(w, 21, 10) + extra
        return None

    def body(self, entry, entries):
        """Addresses reachable inside one function, plus jump tables found."""
        seen = set()
        tables = {}
        work = [entry]
        while work:
            pc = work.pop()
            while self.image.in_text(pc) and pc not in seen:
                seen.add(pc)
                i = self.insn(pc)
                if i.kind in ("op", "bl", "blr", "svc"):
                    pc += 4
                    continue
                if i.kind == "cond":
                    if self.image.in_text(i.target) and (i.target not in entries or i.target == entry):
                        work.append(i.target)
                    pc += 4
                    continue
                if i.kind == "b":
                    if self.image.in_text(i.target) and (i.target not in entries or i.target == entry):
                        work.append(i.target)
                elif i.kind == "br":
                    targets = self.jump_table(pc, i.reg)
                    if targets:
                        tables[pc] = targets
                        work.extend(t for t in targets if self.image.in_text(t))
                break
        return seen, tables


# Emission -----------------------------------------------------------------


def stack_switch(img, pc):
    """Whether pc is mov sp, xN switching to another context's stack, as
    fibers do: xN loaded from memory just before (not from the frame, as an
    sp saved around a variable-sized allocation is), and x30 then restored
    from the new stack before the ret (longjmp loads x30 first, from its
    buffer). Returns N or None."""
    w = img.word(pc)
    if w & 0xFFFFFC1F != 0x9100001F or not img.in_text(pc - 4):
        return None
    n = bits(w, 9, 5)
    prev = img.word(pc - 4)
    loads = prev & 0xFFC00000 == 0xF9400000 or prev & 0xFFE00C00 == 0xF8400000
    if n == 31 or not loads or prev & 31 != n or bits(prev, 9, 5) in (29, 31):
        return None
    for k in range(1, 33):
        if not img.in_text(pc + 4 * k):
            return None
        nxt = img.word(pc + 4 * k)
        if nxt == 0xD65F03C0:  # ret
            return None
        pair = nxt & 0xFFC00000 in (0xA9400000, 0xA8C00000, 0xA9C00000)  # ldp x, x: offset, post, pre
        single = nxt & 0xFFC00000 == 0xF9400000                          # ldr x, [xn, #imm]
        if bits(nxt, 9, 5) == 31 and ((pair and 30 in (nxt & 31, bits(nxt, 14, 10))) or (single and nxt & 31 == 30)):
            return n
    return None


def is_store(w):
    """A load/store-class word that writes memory only (its low five bits name a
    register it reads), or a compare, test or branch, which write no register."""
    if w & 0x0A000000 == 0x08000000:  # loads and stores
        if w & 0x3B000000 == 0x39000000 or w & 0x3B200000 == 0x38000000 or w & 0x3B200000 == 0x38200000:
            return not w & 0x00400000  # single register: L clear for stores
        if w & 0x3A000000 == 0x28000000:  # register pairs
            return not w & 0x00400000
        return False
    if w & 0x1F00001F == 0x0B00001F or w & 0x1F00001F == 0x1100001F or w & 0x1F00001F == 0x0A00001F:
        return True  # cmp, cmn, tst (destination xzr)
    if w & 0x7C000000 == 0x14000000 or w & 0xFF000010 == 0x54000000 or w & 0x7E000000 == 0x34000000 \
            or w & 0x7E000000 == 0x36000000:
        return True  # b, bl, b.cond, cbz/cbnz, tbz/tbnz
    return False


def fname(addr):
    return f"f_{addr:x}"


def emit_function(lifter, entry, entries, out):
    seen, tables = lifter.body(entry, entries)
    order = sorted(seen)
    labels = {entry} if any(
        lifter.insn(a).kind in ("b", "cond") and lifter.insn(a).target == entry for a in order) else set()
    for a in order:
        i = lifter.insn(a)
        if i.kind in ("b", "cond") and i.target in seen:
            labels.add(i.target)
    for targets in tables.values():
        labels.update(targets)
    # Fall-through edges that cross a gap need explicit gotos.
    following = {a: b for a, b in zip(order, order[1:])}
    for a in order:
        i = lifter.insn(a)
        if i.kind in ("op", "bl", "blr", "svc", "cond") and following.get(a) != a + 4:
            if a + 4 in seen:
                labels.add(a + 4)

    out.append(f"void {fname(entry)}(rt::Cpu& c) {{")
    if order[0] != entry:
        # The body reaches code below its entry through branches; start at the entry.
        labels.add(entry)
        out.append(f"    goto L_{entry:x};")
    for a in order:
        i = lifter.insn(a)
        if a in labels:
            out.append(f"L_{a:x}:")
        out.append(f"    c.pc = 0x{a:x}ull;" if lifter.track_pc else f"    // {a:x}")

        def jump(t):
            if t in seen and (t not in entries or t == entry):
                return f"goto L_{t:x};"
            if t in entries:
                return f"{{ {fname(t)}(c); return; }}"
            return f"{{ rt::Call(c, 0x{t:x}ull); return; }}"

        if i.kind == "op":
            out.extend("    " + s for s in i.code)
        elif i.kind == "b":
            out.extend("    " + s for s in i.code)
            out.append("    " + jump(i.target))
        elif i.kind == "cond":
            out.append(f"    if ({i.cond}) {jump(i.target)}")
        elif i.kind == "bl":
            out.append(f"    c.x[30] = 0x{a + 4:x}ull;")
            if i.target in entries:
                out.append(f"    {fname(i.target)}(c);")
            else:
                out.append(f"    rt::Call(c, 0x{i.target:x}ull);")
        elif i.kind == "blr":
            reg = rs(i.reg, 1)
            out.append(f"    {{ u64 t = {reg}; c.x[30] = 0x{a + 4:x}ull; rt::Call(c, t); }}")
        elif i.kind == "ret":
            out.append("    return;")
        elif i.kind == "br":
            reg = rs(i.reg, 1)
            if a in tables:
                cases = " ".join(f"case 0x{t:x}ull: goto L_{t:x};" for t in tables[a])
                out.append(f"    switch ({reg}) {{ {cases} default: rt::BadJump(c, 0x{a:x}ull, {reg}); return; }}")
            else:
                lifter.unresolved_br.append(a)
                out.append(f"    rt::Call(c, {reg}); return;")
        elif i.kind == "svc":
            out.append(f"    rt::Svc(c, 0x{i.imm:x}, 0x{a:x}ull);")
        elif i.kind == "trap":
            lifter.traps[i.imm.split(" #")[0]] += 1
            out.append(f"    rt::Unimplemented(c, 0x{a:x}ull, 0x{lifter.image.word(a):08x}u); return;")
        if a + 4 not in seen and i.kind in ("op", "bl", "blr", "svc", "cond"):
            out.append(f"    rt::Unimplemented(c, 0x{a + 4:x}ull, 0u); return;")
        elif following.get(a) != a + 4 and i.kind in ("op", "bl", "blr", "svc", "cond"):
            out.append(f"    goto L_{a + 4:x};")
    out.append("}")
    out.append("")


PRELUDE = """// Generated by tools/lift.py from a user-supplied module. Do not distribute.
#include "rt/ops.h"
using namespace rt::types;
namespace guest {
"""


def write_if_changed(path, text):
    """Leaves a file that already holds text untouched, so a build only
    recompiles what a new lift changed."""
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def write_module(lifter, outdir, file_span):
    """One file per file_span bytes of guest code, each declaring only the
    functions it calls: a new entry point changes its own file and the table."""
    entries = sorted(lifter.entries())
    entry_set = set(entries)
    outdir.mkdir(parents=True, exist_ok=True)
    files = {}
    for e in entries:
        files.setdefault(e // file_span, []).append(e)
    written = set()
    for key, group in files.items():
        body = []
        for e in group:
            emit_function(lifter, e, entry_set, body)
        called = sorted(set(re.findall(r"\b(f_[0-9a-f]+)\(c\)", "\n".join(body))))
        out = [PRELUDE, *(f"void {f}(rt::Cpu& c);" for f in called), "", *body, "} // namespace guest\n"]
        name = f"lifted_{key * file_span:010x}.cpp"
        write_if_changed(outdir / name, "\n".join(out))
        written.add(name)
    for old in outdir.glob("lifted_*.cpp"):
        if old.name not in written and old.name != "lifted_table.cpp":
            old.unlink()
    (outdir / "lifted.h").unlink(missing_ok=True)
    table = [PRELUDE, *(f"void {fname(e)}(rt::Cpu& c);" for e in entries), "} // namespace guest", "",
             "const rt::FunctionEntry rt_functions[] = {"]
    table += [f"    {{0x{e:x}ull, guest::{fname(e)}}}," for e in entries]
    table += ["};", f"const size_t rt_function_count = {len(entries)};",
              f"const uint64_t rt_module_entry = 0x{lifter.image.entry:x}ull;", ""]
    write_if_changed(outdir / "lifted_table.cpp", "\n".join(table))
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("outdir")
    ap.add_argument("--module", action="append", default=[], metavar="ELF",
                    help="another module loaded with the first (repeat, in load order after it); "
                         "the first is where the process starts")
    ap.add_argument("--file-span", type=lambda v: int(v, 0), default=0x20000,
                    help="bytes of guest code per generated file")
    ap.add_argument("--track-pc", action="store_true", help="store the guest pc before every instruction")
    args = ap.parse_args()
    if args.module:
        image = Program([Image(args.elf)] + [Image(m) for m in args.module])
    else:
        image = Image(args.elf)
    lifter = Lifter(image)
    lifter.track_pc = args.track_pc
    entries = write_module(lifter, Path(args.outdir), args.file_span)
    print(f"{len(entries)} functions, {len(lifter.cache)} instructions lifted")
    print(f"{len(lifter.unresolved_br)} indirect branches without a recognised jump table")
    if lifter.traps:
        print("traps: " + ", ".join(f"{k} x{v}" for k, v in lifter.traps.most_common()))


if __name__ == "__main__":
    sys.exit(main())
