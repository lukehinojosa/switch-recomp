"""Read system NCAs from a locally supplied firmware folder.

Covers what the sysmodule work needs: the NCA header, the key area, AES-CTR
sections, PFS0 (ExeFS) and NPDM service access control. Key values are read
from the user's own prod.keys and are never printed.
"""
import argparse
import struct
import sys
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

CONTENT_TYPES = {0: "Program", 1: "Meta", 2: "Control", 3: "Manual", 4: "Data", 5: "PublicData"}


def load_keys(path):
    keys = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep:
            keys[name.strip()] = bytes.fromhex(value.strip())
    return keys


def xts_decrypt(key, data, first_sector, sector_size=0x200):
    """AES-128-XTS with Nintendo's big-endian sector tweak."""
    data_cipher = AES.new(key[:16], AES.MODE_ECB)
    tweak_cipher = AES.new(key[16:32], AES.MODE_ECB)
    out = bytearray()
    for i in range(0, len(data), sector_size):
        tweak = int.from_bytes(tweak_cipher.encrypt((first_sector + i // sector_size).to_bytes(16, "big")), "little")
        sector = data[i:i + sector_size]
        for j in range(0, len(sector), 16):
            t = tweak.to_bytes(16, "little")
            block = bytes(a ^ b for a, b in zip(sector[j:j + 16], t))
            out += bytes(a ^ b for a, b in zip(data_cipher.decrypt(block), t))
            tweak <<= 1
            if tweak >> 128:
                tweak = (tweak & ((1 << 128) - 1)) ^ 0x87
    return bytes(out)


class Nca:
    def __init__(self, path, keys):
        self.path = Path(path)
        with open(self.path, "rb") as f:
            raw = f.read(0xC00)
        self.header = xts_decrypt(keys["header_key"], raw, 0)
        if self.header[0x200:0x204] != b"NCA3":
            raise ValueError(f"{self.path.name}: not an NCA3 header")
        h = self.header
        self.content_type = h[0x205]
        self.program_id = struct.unpack_from("<Q", h, 0x210)[0]
        self.rights_id = h[0x230:0x240]
        generation = max(h[0x206], h[0x220])
        index = generation - 1 if generation else 0
        kak_kind = ("application", "ocean", "system")[h[0x207]]
        kak = keys.get(f"key_area_key_{kak_kind}_{index:02x}")
        self.key_area = None
        if kak and not any(self.rights_id):
            self.key_area = AES.new(kak, AES.MODE_ECB).decrypt(h[0x300:0x340])
        self.sections = []
        for i in range(4):
            start, end = struct.unpack_from("<II", h, 0x240 + i * 0x10)
            if end:
                self.sections.append((i, start * 0x200, (end - start) * 0x200, h[0x400 + i * 0x200:0x600 + i * 0x200]))

    def read_section(self, index, offset, size):
        _, base, _, fs = next(s for s in self.sections if s[0] == index)
        encryption = fs[4]
        aligned = offset & ~0xF
        with open(self.path, "rb") as f:
            f.seek(base + aligned)
            data = f.read(size + (offset - aligned))
        if encryption == 1:
            plain = data
        elif encryption == 3:
            if self.key_area is None:
                raise ValueError(f"{self.path.name}: no key-area key for this generation")
            upper = fs[0x140:0x148][::-1]
            ctr = Counter.new(64, prefix=upper, initial_value=(base + aligned) >> 4)
            plain = AES.new(self.key_area[0x20:0x30], AES.MODE_CTR, counter=ctr).decrypt(data)
        else:
            raise ValueError(f"{self.path.name}: section encryption {encryption} not supported")
        return plain[offset - aligned:]

    def pfs0(self, index):
        """Return {name: (offset, size)} for a hierarchical-SHA256 PFS0 section."""
        fs = next(s for s in self.sections if s[0] == index)[3]
        if fs[2] != 1 or fs[3] != 2:
            raise ValueError("section is not a PFS0 with SHA-256 hashing")
        pfs_offset = struct.unpack_from("<Q", fs, 0x40)[0]
        head = self.read_section(index, pfs_offset, 0x10)
        if head[:4] != b"PFS0":
            raise ValueError("PFS0 magic missing")
        count, strings = struct.unpack_from("<II", head, 4)
        table = self.read_section(index, pfs_offset, 0x10 + count * 0x18 + strings)
        names = table[0x10 + count * 0x18:]
        data_start = pfs_offset + 0x10 + count * 0x18 + strings
        files = {}
        for i in range(count):
            off, size, name_off = struct.unpack_from("<QQI", table, 0x10 + i * 0x18)
            name = names[name_off:names.index(b"\0", name_off)].decode()
            files[name] = (data_start + off, size)
        return files

    def read_file(self, index, name):
        offset, size = self.pfs0(index)[name]
        return self.read_section(index, offset, size)


def npdm_services(npdm):
    """Return (title name, hosted services, client services) from NPDM ACI0."""
    if npdm[:4] != b"META":
        raise ValueError("NPDM magic missing")
    name = npdm[0x20:0x30].split(b"\0")[0].decode(errors="replace")
    aci_offset, _ = struct.unpack_from("<II", npdm, 0x70)
    aci = npdm[aci_offset:]
    sac_offset, sac_size = struct.unpack_from("<II", aci, 0x28)
    sac = aci[sac_offset:sac_offset + sac_size]
    hosted, used = [], []
    i = 0
    while i < len(sac):
        control = sac[i]
        length = (control & 7) + 1
        service = sac[i + 1:i + 1 + length].decode(errors="replace")
        (hosted if control & 0x80 else used).append(service)
        i += 1 + length
    return name, hosted, used


def scan(firmware, keys):
    for path in sorted(Path(firmware).glob("*.nca")):
        if path.name.endswith(".cnmt.nca"):
            continue
        try:
            nca = Nca(path, keys)
            if nca.content_type != 0 or not nca.sections:
                continue
            files = nca.pfs0(0)
            if "main.npdm" not in files:
                continue
            yield nca, files, npdm_services(nca.read_file(0, "main.npdm"))
        except (ValueError, KeyError, StopIteration) as error:
            print(f"skip {path.name}: {error}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keys", required=True)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--host", help="only list modules hosting a service with this prefix")
    parser.add_argument("--extract", help="write each matching module's ExeFS files under this folder")
    args = parser.parse_args()
    keys = load_keys(args.keys)
    for nca, files, (name, hosted, used) in scan(args.firmware, keys):
        if args.host and not any(s.startswith(args.host) for s in hosted):
            continue
        print(f"{nca.program_id:016x} {name:<12} {nca.path.name}")
        print(f"  exefs:  {', '.join(sorted(files))}")
        print(f"  hosts:  {', '.join(hosted) or '-'}")
        print(f"  uses:   {', '.join(used) or '-'}")
        if args.extract:
            out = Path(args.extract) / f"{nca.program_id:016x}-{name}"
            out.mkdir(parents=True, exist_ok=True)
            for file in files:
                (out / file).write_bytes(nca.read_file(0, file))


if __name__ == "__main__":
    main()
