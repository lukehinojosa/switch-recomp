"""Turn an NSO into a relocated AArch64 ELF for disassemblers.

Decompresses the three segments, applies the module's relative relocations
(RELA and RELR) at the chosen base, and writes one PT_LOAD per segment with
its real permissions plus the .bss.
"""
import argparse
import hashlib
import struct
from pathlib import Path

DT_NULL, DT_RELA, DT_RELASZ, DT_RELAENT = 0, 7, 8, 9
DT_RELRSZ, DT_RELR = 35, 36
R_AARCH64_RELATIVE = 0x403


def lz4_block(src, size):
    out = bytearray()
    i = 0
    while i < len(src):
        token = src[i]
        i += 1
        literals = token >> 4
        if literals == 15:
            while True:
                b = src[i]
                i += 1
                literals += b
                if b != 255:
                    break
        out += src[i:i + literals]
        i += literals
        if i >= len(src):
            break
        offset = src[i] | src[i + 1] << 8
        i += 2
        length = token & 15
        if length == 15:
            while True:
                b = src[i]
                i += 1
                length += b
                if b != 255:
                    break
        length += 4
        start = len(out) - offset
        for k in range(length):
            out.append(out[start + k])
    if len(out) != size:
        raise ValueError(f"LZ4 produced {len(out):#x} bytes, expected {size:#x}")
    return bytes(out)


def load_nso(data):
    if data[:4] != b"NSO0":
        raise ValueError("not an NSO")
    flags = struct.unpack_from("<I", data, 0xC)[0]
    segments = []
    for i in range(3):
        file_off, mem_off, size = struct.unpack_from("<III", data, 0x10 + i * 0x10)
        csize = struct.unpack_from("<I", data, 0x60 + i * 4)[0]
        raw = data[file_off:file_off + csize]
        body = lz4_block(raw, size) if flags & (1 << i) else raw
        if flags & (1 << (i + 3)):
            expected = data[0xA0 + i * 0x20:0xC0 + i * 0x20]
            if hashlib.sha256(body).digest() != expected:
                raise ValueError(f"segment {i} hash mismatch")
        segments.append((mem_off, body))
    bss = struct.unpack_from("<I", data, 0x3C)[0]
    build_id = data[0x40:0x60]
    return segments, bss, build_id


def relocate(image, base):
    mod0 = struct.unpack_from("<I", image, 4)[0]
    if image[mod0:mod0 + 4] != b"MOD0":
        raise ValueError("MOD0 header missing")
    dynamic = mod0 + struct.unpack_from("<i", image, mod0 + 4)[0]
    tags = {}
    i = dynamic
    while True:
        tag, value = struct.unpack_from("<QQ", image, i)
        if tag == DT_NULL:
            break
        tags[tag] = value
        i += 16
    applied = 0
    if DT_RELA in tags:
        entry = tags.get(DT_RELAENT, 24)
        for off in range(tags[DT_RELA], tags[DT_RELA] + tags[DT_RELASZ], entry):
            where, info, addend = struct.unpack_from("<QQq", image, off)
            if info & 0xFFFFFFFF == R_AARCH64_RELATIVE:
                struct.pack_into("<Q", image, where, base + addend)
                applied += 1
    if DT_RELR in tags:
        where = 0
        for off in range(tags[DT_RELR], tags[DT_RELR] + tags[DT_RELRSZ], 8):
            entry = struct.unpack_from("<Q", image, off)[0]
            if entry & 1 == 0:
                where = entry
                value = struct.unpack_from("<Q", image, where)[0]
                struct.pack_into("<Q", image, where, base + value)
                applied += 1
                where += 8
            else:
                bits = entry >> 1
                for k in range(63):
                    if bits >> k & 1:
                        at = where + k * 8
                        value = struct.unpack_from("<Q", image, at)[0]
                        struct.pack_into("<Q", image, at, base + value)
                        applied += 1
                where += 63 * 8
    return applied


def write_elf(path, segments, bss, base):
    # Segment memory offsets are page aligned; place each at the same file offset.
    end = max(off + len(body) for off, body in segments)
    perms = (5, 4, 6)  # r-x, r--, rw-
    phnum = 3
    header_size = 0x40 + phnum * 0x38
    file_base = (header_size + 0xFFF) & ~0xFFF
    blob = bytearray(file_base + end)
    for off, body in segments:
        blob[file_base + off:file_base + off + len(body)] = body
    struct.pack_into("<16sHHIQQQIHHHHHH", blob, 0,
                     b"\x7fELF\x02\x01\x01" + bytes(9), 2, 183, 1,
                     base, 0x40, 0, 0, 0x40, 0x38, phnum, 0x40, 0, 0)
    for i, (off, body) in enumerate(segments):
        memsz = bss_end(segments, bss) - off if i == 2 else len(body)
        struct.pack_into("<IIQQQQQQ", blob, 0x40 + i * 0x38, 1, perms[i],
                         file_base + off, base + off, base + off, len(body), memsz, 0x1000)
    Path(path).write_bytes(blob)


def bss_end(segments, bss):
    data_off, data = segments[2]
    return data_off + ((len(data) + 0xFFF) & ~0xFFF) + bss if bss else data_off + len(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("nso")
    parser.add_argument("output")
    parser.add_argument("--base", type=lambda v: int(v, 0), default=0x7100000000)
    args = parser.parse_args()
    segments, bss, build_id = load_nso(Path(args.nso).read_bytes())
    image = bytearray(max(off + len(body) for off, body in segments))
    for off, body in segments:
        image[off:off + len(body)] = body
    applied = relocate(image, args.base)
    segments = [(off, bytes(image[off:off + len(body)])) for off, body in segments]
    write_elf(args.output, segments, bss, args.base)
    print(f"build id {build_id.hex()}")
    for name, (off, body) in zip(("text", "rodata", "data"), segments):
        print(f"{name:<7}{args.base + off:#x} size {len(body):#x}")
    print(f"bss    {bss:#x} bytes; {applied} relocations applied")


if __name__ == "__main__":
    main()
