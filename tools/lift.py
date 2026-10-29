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
  - Instructions the decoder does not know become rt::Unimplemented traps, and
    are counted in the report, so a partial lift still builds.
"""
import argparse
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

        # Scalar double precision.
        if m(0xFFFFFC00, 0x1E604000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{c.q[{rn}].lo, 0}};"])
        if m(0xFFFFFC00, 0x1E60C000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{c.q[{rn}].lo & 0x7fffffffffffffffull, 0}};"])
        if m(0xFFFFFC00, 0x1E614000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{c.q[{rn}].lo ^ 0x8000000000000000ull, 0}};"])
        for val, fn in ((0x1E602800, "Fadd"), (0x1E603800, "Fsub"), (0x1E600800, "Fmul"), (0x1E601800, "Fdiv")):
            if m(0xFFE0FC00, val):
                return Insn("op", [setd(rd, f"rt::{fn}({D(rn)}, {D(rm)})")])
        if m(0xFFE08000, 0x1F400000):
            ra = bits(w, 14, 10)
            return Insn("op", [setd(rd, f"rt::Fmadd({D(rn)}, {D(rm)}, {D(ra)})")])
        if m(0xFFE0FC1F, 0x1E602000):
            return Insn("op", [f"rt::Fcmp(c, {D(rn)}, {D(rm)});"])
        if m(0xFFFFFC1F, 0x1E602008):
            return Insn("op", [f"rt::Fcmp(c, {D(rn)}, 0.0);"])
        if m(0xFFE00C00, 0x1E600C00):
            cond = CONDS[bits(w, 15, 12)]
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{({cond}) ? c.q[{rn}].lo : c.q[{rm}].lo, 0}};"])
        if m(0xFFFFFC00, 0x1E624000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{rt::FloatBits(float({D(rn)})), 0}};"])
        if m(0xFFE01FE0, 0x1E601000):
            return Insn("op", [f"c.q[{rd}] = rt::Vec{{0x{vfp_expand_imm64(bits(w, 20, 13)):x}ull, 0}};"])
        if m(0x7FFFFC00, 0x1E780000) or m(0x7FFFFC00, 0x1E790000):
            sf = w >> 31
            fn = ("Fcvtzu" if bits(w, 16, 16) else "Fcvtzs") + ("64" if sf else "32")
            return Insn("op", [wr(rd, sf, f"rt::{fn}({D(rn)})")])
        if m(0x7FFFFC00, 0x1E620000) or m(0x7FFFFC00, 0x1E630000):
            sf = w >> 31
            unsigned = bits(w, 16, 16)
            src = rs(rn, sf)
            cast = ("u64" if sf else "u32") if unsigned else ("s64" if sf else "s32")
            return Insn("op", [setd(rd, f"double({cast}({src}))")])
        if m(0xFFFFFC00, 0x5E61D800):
            return Insn("op", [setd(rd, f"double(s64(c.q[{rn}].lo))")])
        if m(0xFFFFFC00, 0x7E61D800):
            return Insn("op", [setd(rd, f"double(c.q[{rn}].lo)")])
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
        raise Unsupported()


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

    def dynamic_entries(self):
        """DT_INIT and DT_FINI: functions the module's startup code calls by
        offset from the module base, so no pointer to them exists."""
        base = self.text_base
        raw = self.read(base + 4, 4)
        if raw is None:
            return set()
        mod0 = base + struct.unpack("<I", raw)[0]
        if self.read(mod0, 4) != b"MOD0":
            return set()
        at = mod0 + struct.unpack("<i", self.read(mod0 + 4, 4))[0]
        found = set()
        while True:
            entry = self.read(at, 16)
            if entry is None:
                break
            tag, value = struct.unpack("<QQ", entry)
            if tag == 0:
                break
            if tag in (12, 13) and self.in_text(base + value):  # DT_INIT, DT_FINI
                found.add(base + value)
            at += 16
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
            self.cache[pc] = self.decoder.decode(pc, self.image.word(pc))
        return self.cache[pc]

    def entries(self):
        """Entry points: the module entry, every BL target, code addresses
        built by ADR/ADRP+ADD, code addresses stored in data, and DT_INIT and
        DT_FINI."""
        img = self.image
        found = {img.entry}
        for pc in range(img.text_base, img.text_end, 4):
            w = img.word(pc)
            if w & 0xFC000000 == 0x94000000:
                t = (pc + (sext(w & 0x3FFFFFF, 26) << 2)) & M64
                if img.in_text(t):
                    found.add(t)
            elif w & 0x9F000000 == 0x10000000:  # adr
                t = (pc + sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21)) & M64
                if img.in_text(t):
                    found.add(t)
            elif w & 0x9F000000 == 0x90000000 and pc + 4 < img.text_end:  # adrp + add
                page = (pc & ~0xFFF) + (sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21) << 12)
                nxt = img.word(pc + 4)
                rd = w & 31
                if nxt & 0xFFC00000 == 0x91000000 and bits(nxt, 9, 5) == rd:
                    t = (page + bits(nxt, 21, 10)) & M64
                    if img.in_text(t):
                        found.add(t)
        found.update(img.dynamic_entries())
        for va, blob, _, flags in img.segments:
            if flags & 1:
                continue
            for off in range(0, len(blob) - 7, 8):
                t = struct.unpack_from("<Q", blob, off)[0]
                if img.in_text(t):
                    found.add(t)
        return found

    def jump_table(self, pc, reg):
        """Recognise adr xB, L; ldr{b,h} wO, [xT, xI{, lsl}]; add xB, xB, xO, lsl #2; br xB.

        Returns the list of targets, or None.
        """
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

    def find_constant(self, pc, reg):
        """Value of reg at pc if set by adr, or adrp+add, within this function's linear prefix."""
        img = self.image
        a = pc - 4
        for _ in range(256):
            if not img.in_text(a):
                return None
            w = img.word(a)
            if w & 0x9F000000 == 0x10000000 and w & 31 == reg:
                return (a + sext(bits(w, 23, 5) << 2 | bits(w, 30, 29), 21)) & M64
            if w & 0xFFC00000 == 0x91000000 and w & 31 == reg and bits(w, 9, 5) == reg:
                p = img.word(a - 4) if img.in_text(a - 4) else 0
                if p & 0x9F000000 == 0x90000000 and p & 31 == reg:
                    page = ((a - 4) & ~0xFFF) + (sext(bits(p, 23, 5) << 2 | bits(p, 30, 29), 21) << 12)
                    return (page + bits(w, 21, 10)) & M64
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


def write_module(lifter, outdir, per_file):
    entries = sorted(lifter.entries())
    entry_set = set(entries)
    outdir.mkdir(parents=True, exist_ok=True)
    for old in outdir.glob("lifted_*.cpp"):
        old.unlink()
    decls = [f"void {fname(e)}(rt::Cpu& c);" for e in entries]
    header = ["#pragma once", '#include "rt/ops.h"', "namespace guest {", *decls, "}", ""]
    (outdir / "lifted.h").write_text("\n".join(header))
    for n in range(0, len(entries), per_file):
        out = [PRELUDE.replace('#include "rt/ops.h"', '#include "lifted.h"')]
        for e in entries[n:n + per_file]:
            emit_function(lifter, e, entry_set, out)
        out.append("} // namespace guest\n")
        (outdir / f"lifted_{n // per_file:04d}.cpp").write_text("\n".join(out))
    table = [PRELUDE.replace('#include "rt/ops.h"', '#include "lifted.h"'), "} // namespace guest", "",
             "const rt::FunctionEntry rt_functions[] = {"]
    table += [f"    {{0x{e:x}ull, guest::{fname(e)}}}," for e in entries]
    table += ["};", f"const size_t rt_function_count = {len(entries)};",
              f"const uint64_t rt_module_entry = 0x{lifter.image.entry:x}ull;", ""]
    (outdir / "lifted_table.cpp").write_text("\n".join(table))
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("elf")
    ap.add_argument("outdir")
    ap.add_argument("--per-file", type=int, default=400)
    ap.add_argument("--track-pc", action="store_true", help="store the guest pc before every instruction")
    args = ap.parse_args()
    lifter = Lifter(Image(args.elf))
    lifter.track_pc = args.track_pc
    entries = write_module(lifter, Path(args.outdir), args.per_file)
    print(f"{len(entries)} functions, {len(lifter.cache)} instructions lifted")
    print(f"{len(lifter.unresolved_br)} indirect branches without a recognised jump table")
    if lifter.traps:
        print("traps: " + ", ".join(f"{k} x{v}" for k, v in lifter.traps.most_common()))


if __name__ == "__main__":
    sys.exit(main())
