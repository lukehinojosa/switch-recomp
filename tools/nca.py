"""Read system NCAs from a locally supplied firmware folder.

Covers what the sysmodule work needs: the NCA header, the key area, AES-CTR
sections, PFS0 (ExeFS) and NPDM service access control. Key values are read
from the user's own prod.keys and are never printed.
"""
import argparse
import bisect
import hashlib
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
    def __init__(self, path, keys, offset=0, titlekey=None):
        """An NCA file, or one stored at offset inside a container such as an NSP.

        An NCA with a rights ID is encrypted with its title key, which a
        ticket carries (see ticket_titlekey); titlekey is that key, decrypted.
        """
        self.path = Path(path)
        self.offset = offset
        with open(self.path, "rb") as f:
            f.seek(offset)
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
        self.key_generation = index
        self.ctr_key = None
        if any(self.rights_id):
            self.ctr_key = titlekey
        elif kak:
            self.ctr_key = AES.new(kak, AES.MODE_ECB).decrypt(h[0x300:0x340])[0x20:0x30]
        self.sections = []
        for i in range(4):
            start, end = struct.unpack_from("<II", h, 0x240 + i * 0x10)
            if end:
                self.sections.append((i, start * 0x200, (end - start) * 0x200, h[0x400 + i * 0x200:0x600 + i * 0x200]))

    def read_section(self, index, offset, size, generation=None):
        """Read decrypted section bytes. In a patch section (AES-CTR-Ex), data
        regions take the generation of their subsection; its tables take none."""
        _, base, _, fs = next(s for s in self.sections if s[0] == index)
        encryption = fs[4]
        aligned = offset & ~0xF
        with open(self.path, "rb") as f:
            f.seek(self.offset + base + aligned)
            data = f.read(size + (offset - aligned))
        if encryption == 1:
            plain = data
        elif encryption in (3, 4):
            if self.ctr_key is None:
                raise ValueError(f"{self.path.name}: no key for this NCA (key-area key or title key)")
            upper = fs[0x140:0x148][::-1]
            if generation is not None:
                upper = upper[:4] + generation.to_bytes(4, "big")
            ctr = Counter.new(64, prefix=upper, initial_value=(base + aligned) >> 4)
            plain = AES.new(self.ctr_key, AES.MODE_CTR, counter=ctr).decrypt(data)
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

    def fs_header(self, index):
        return next(s for s in self.sections if s[0] == index)[3]

    def romfs_section(self):
        """Return the index of the RomFS (IVFC hashed) section."""
        for index, _, _, fs in self.sections:
            if fs[2] == 0 and fs[3] == 3 and fs[8:12] == b"IVFC":
                return index
        raise ValueError(f"{self.path.name}: no RomFS section")

    def romfs_root_file(self, index, name):
        """Return a file in the root directory of a RomFS section (IVFC hashed)."""
        fs = self.fs_header(index)
        if fs[2] != 0 or fs[3] != 3 or fs[8:12] != b"IVFC":
            raise ValueError("section is not a RomFS with IVFC hashing")
        romfs = ivfc_level(fs, 5)[0]
        header = struct.unpack("<10Q", self.read_section(index, romfs, 0x50))
        file_meta_offset, file_meta_size, data_offset = header[7], header[8], header[9]
        table = self.read_section(index, romfs + file_meta_offset, file_meta_size)
        at = 0
        while at + 0x20 <= len(table):
            parent, _, offset, size, _, name_size = struct.unpack_from("<IIQQII", table, at)
            entry_name = table[at + 0x20:at + 0x20 + name_size].decode()
            if parent == 0 and entry_name == name:
                return self.read_section(index, romfs + data_offset + offset, size)
            at += 0x20 + ((name_size + 3) & ~3)
        raise KeyError(name)


def ivfc_level(fs, level):
    """Return (offset, size, block size) of an IVFC level; level 5 holds the RomFS."""
    offset, size, order = struct.unpack_from("<QQI", fs, 0x18 + level * 0x18)
    return offset, size, 1 << order


def bucket_tree(table, header, entry_format):
    """Return (entries, end offset) of a bucket tree (one L1 node, then entry sets).

    header is the tree's 0x10-byte "BKTR" header from the section's patch info."""
    magic, _, count, _ = struct.unpack("<4sIiI", header)
    if magic != b"BKTR" or count <= 0:
        raise ValueError("bucket tree header invalid")
    node = 0x4000
    entry_size = struct.calcsize(entry_format)
    sets = -(-count // ((node - 0x10) // entry_size))
    index, l1_count, end = struct.unpack_from("<iiq", table, 0)
    if index != 0 or l1_count != sets or len(table) < node * (1 + sets):
        raise ValueError("bucket tree needs more than one L1 node, or is truncated")
    entries = []
    for s in range(sets):
        at = node * (1 + s)
        _, n, _ = struct.unpack_from("<iiq", table, at)
        entries += [struct.unpack_from(entry_format, table, at + 0x10 + i * entry_size) for i in range(n)]
    if len(entries) != count:
        raise ValueError("bucket tree entry count mismatch")
    return entries, end


class PatchedSection:
    """A patch (BKTR) section of an update NCA, read over its base NCA's section.

    Its indirect table maps each virtual range to the base section or to the
    patch's own data, which is AES-CTR-Ex encrypted with per-subsection
    generations."""

    def __init__(self, base, base_index, patch, patch_index):
        self.base, self.base_index, self.patch, self.patch_index = base, base_index, patch, patch_index
        fs = patch.fs_header(patch_index)
        if fs[4] != 4:
            raise ValueError(f"{patch.path.name}: section {patch_index} is not a patch section")
        indirect_offset, indirect_size = struct.unpack_from("<QQ", fs, 0x100)
        ctr_offset, ctr_size = struct.unpack_from("<QQ", fs, 0x120)
        indirect, self.size = bucket_tree(patch.read_section(patch_index, indirect_offset, indirect_size),
                                          fs[0x110:0x120], "<QQi")
        subsections, self.data_end = bucket_tree(patch.read_section(patch_index, ctr_offset, ctr_size),
                                                 fs[0x130:0x140], "<QII")
        self.virtual = [e[0] for e in indirect]
        self.indirect = indirect
        self.sub_offsets = [e[0] for e in subsections]
        self.subsections = subsections

    def _read_patch(self, offset, size):
        out = bytearray()
        while size:
            i = bisect.bisect_right(self.sub_offsets, offset) - 1
            end = self.sub_offsets[i + 1] if i + 1 < len(self.sub_offsets) else self.data_end
            n = min(size, end - offset)
            if i < 0 or n <= 0:
                raise ValueError(f"patch offset {offset:#x} outside its subsections")
            out += self.patch.read_section(self.patch_index, offset, n, self.subsections[i][2])
            offset += n
            size -= n
        return bytes(out)

    def read(self, offset, size):
        out = bytearray()
        while size:
            i = bisect.bisect_right(self.virtual, offset) - 1
            end = self.virtual[i + 1] if i + 1 < len(self.virtual) else self.size
            n = min(size, end - offset)
            if i < 0 or n <= 0:
                raise ValueError(f"virtual offset {offset:#x} outside the indirect table")
            _, physical, storage = self.indirect[i]
            physical += offset - self.virtual[i]
            if storage == 0:
                out += self.base.read_section(self.base_index, physical, n)
            elif storage == 1:
                out += self._read_patch(physical, n)
            else:
                raise ValueError(f"indirect storage index {storage}")
            offset += n
            size -= n
        return bytes(out)


def write_romfs(read, fs, out, report=None):
    """Write IVFC level 5 (the RomFS image) of a section through read(offset, size),
    checking every block against its level-4 SHA-256. Returns the block count."""
    data_offset, data_size, block = ivfc_level(fs, 5)
    hash_offset, hash_size, _ = ivfc_level(fs, 4)
    hashes = read(hash_offset, hash_size)
    blocks = -(-data_size // block)
    if hash_size < blocks * 32:
        raise ValueError("IVFC level 4 too small for level 5")
    chunk = block * max(1, (8 << 20) // block)
    with open(out, "wb") as f:
        for at in range(0, data_size, chunk):
            data = read(data_offset + at, min(chunk, data_size - at))
            for b in range(0, len(data), block):
                piece = data[b:b + block]
                if len(piece) < block:
                    piece += bytes(block - len(piece))
                k = (at + b) // block
                if hashlib.sha256(piece).digest() != hashes[k * 32:k * 32 + 32]:
                    raise ValueError(f"RomFS block {k} at {at + b:#x} fails its IVFC hash")
            f.write(data)
            if report:
                report(at + len(data), data_size)
    return blocks


def pfs0_entries(path):
    """Return {name: (offset, size)} for a plain PFS0 container such as an NSP."""
    with open(path, "rb") as f:
        magic, count, strings, _ = struct.unpack("<4sIII", f.read(0x10))
        if magic != b"PFS0":
            raise ValueError(f"{Path(path).name}: not a PFS0 container")
        table = f.read(count * 0x18 + strings)
    names = table[count * 0x18:]
    data_start = 0x10 + count * 0x18 + strings
    entries = {}
    for i in range(count):
        offset, size, name_offset = struct.unpack_from("<QQI", table, i * 0x18)
        entries[names[name_offset:names.index(b"\0", name_offset)].decode()] = (data_start + offset, size)
    return entries


def hfs0_entries(path, offset):
    """Return {name: (offset, size)} for an HFS0 partition at offset in a file."""
    with open(path, "rb") as f:
        f.seek(offset)
        magic, count, strings, _ = struct.unpack("<4sIII", f.read(0x10))
        if magic != b"HFS0":
            raise ValueError(f"{Path(path).name}: no HFS0 partition at {offset:#x}")
        table = f.read(count * 0x40 + strings)
    names = table[count * 0x40:]
    data_start = offset + 0x10 + count * 0x40 + strings
    entries = {}
    for i in range(count):
        entry_offset, size, name_offset = struct.unpack_from("<QQI", table, i * 0x40)
        entries[names[name_offset:names.index(b"\0", name_offset)].decode()] = (data_start + entry_offset, size)
    return entries


def container_entries(path):
    """Return the files of an NSP, or of an XCI's secure partition."""
    with open(path, "rb") as f:
        f.seek(0x100)
        head = f.read(0x40)
    if head[:4] == b"HEAD":
        root = hfs0_entries(path, struct.unpack_from("<Q", head, 0x30)[0])
        return hfs0_entries(path, root["secure"][0])
    return pfs0_entries(path)


def ticket_titlekey(ticket, key_generation, keys):
    """Decrypt the title key of a common ticket (RSA-2048 signed) with titlekek."""
    if struct.unpack_from("<I", ticket, 0)[0] != 0x10004:
        raise ValueError("ticket is not RSA-2048 signed")
    if ticket[0x281] != 0: # title key type: 0 common, 1 personalized
        raise ValueError("ticket is personalized, not common")
    titlekek = keys[f"titlekek_{key_generation:02x}"]
    return AES.new(titlekek, AES.MODE_ECB).decrypt(ticket[0x180:0x190])


def program_nca(path, keys, patch=None):
    """Return the Program NCA in an NSP or XCI, decrypted with the container's
    own ticket. patch selects an update's patch NCA (True) or a full one (False);
    an XCI can carry both."""
    entries = container_entries(path)
    tickets = {}
    for name, (offset, size) in entries.items():
        if name.endswith(".tik"):
            with open(path, "rb") as f:
                f.seek(offset)
                ticket = f.read(size)
            tickets[ticket[0x2A0:0x2B0]] = ticket
    for name, (offset, _) in entries.items():
        if not name.endswith(".nca") or name.endswith(".cnmt.nca"):
            continue
        nca = Nca(path, keys, offset)
        if nca.content_type != 0:
            continue
        if patch is not None and patch != any(fs[4] == 4 for _, _, _, fs in nca.sections):
            continue
        if any(nca.rights_id):
            if nca.rights_id not in tickets:
                raise ValueError(f"{Path(path).name}: no ticket for the Program NCA")
            nca = Nca(path, keys, offset, ticket_titlekey(tickets[nca.rights_id], nca.key_generation, keys))
        return nca
    raise ValueError(f"{Path(path).name}: no {'patch ' if patch else ''}Program NCA")


def nsp_control_nacp(nsp, keys):
    """Return (program id, control.nacp) from the Control NCA in an NSP."""
    for name, (offset, _) in pfs0_entries(nsp).items():
        if not name.endswith(".nca") or name.endswith(".cnmt.nca"):
            continue
        nca = Nca(nsp, keys, offset)
        if nca.content_type == 2:
            return nca.program_id, nca.romfs_root_file(0, "control.nacp")
    raise ValueError(f"{Path(nsp).name}: no Control NCA")


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


# ncm's storage ids, as content meta headers and lr name them.
STORAGE_BUILT_IN_SYSTEM, STORAGE_BUILT_IN_USER = 3, 4
STORAGE_NAMES = {STORAGE_BUILT_IN_SYSTEM: "BuiltInSystem", STORAGE_BUILT_IN_USER: "BuiltInUser"}


def content_info(content_id, size, content_type, id_offset=0):
    """An ncm ContentInfo: content id, 40-bit size, attributes, type, id offset."""
    return content_id + size.to_bytes(5, "little") + bytes([0, content_type, id_offset])


def installed_content_meta(cnmt, meta_id, meta_size, storage):
    """Convert a packaged content meta (the .cnmt in a Meta NCA) to the value
    ncm keeps in its database, and its ContentMetaKey.

    Packaged: id, version, type, platform, extended header size, content
    count, content meta count, attributes (0x20 bytes), the extended header,
    PackagedContentInfo[] (a SHA-256 then a ContentInfo), ContentMetaInfo[].
    Installed: extended header size, content count, content meta count,
    attributes, storage id (8 bytes), the extended header, ContentInfo[] with
    the Meta NCA itself first (as ncm's installer writes it), ContentMetaInfo[].
    """
    meta_id_, version, meta_type, _, ext_size, count, meta_count, attributes = \
        struct.unpack_from("<QIBBHHHB", cnmt, 0)
    extended = cnmt[0x20:0x20 + ext_size]
    infos = [content_info(meta_id, meta_size, 0)]
    at = 0x20 + ext_size
    for i in range(count):
        infos.append(cnmt[at + 0x20:at + 0x38])
        at += 0x38
    metas = cnmt[at:at + meta_count * 0x10]
    header = struct.pack("<HHHBB", ext_size, count + 1, meta_count, attributes, storage)
    key = struct.pack("<QIBBxx", meta_id_, version, meta_type, 0) # install type: full
    return key, header + extended + b"".join(infos) + metas


def write_content_meta(out, storage, nca, content_id, size, location):
    """Write one Meta NCA's content meta under out/<storage>/ and return its key."""
    files = nca.pfs0(0)
    name = next(n for n in files if n.endswith(".cnmt"))
    key, value = installed_content_meta(nca.read_file(0, name), content_id, size, storage)
    meta_id, version, meta_type, install = struct.unpack_from("<QIBB", key, 0)
    folder = Path(out) / STORAGE_NAMES[storage]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{meta_id:016x}_{version}_{meta_type}_{install}.meta").write_bytes(value)
    return meta_id, version, meta_type


def write_content_index(out, firmware, packages, keys):
    """The firmware's content metas as BuiltInSystem's, and those of the
    packages (NSP or XCI) as installed in BuiltInUser, with contents.txt in
    each storage: where every content's NCA is (content id, offset, size, its
    rights ID and key generation as ncm reports them, file)."""
    locations = {STORAGE_BUILT_IN_SYSTEM: [], STORAGE_BUILT_IN_USER: []}
    count = 0
    if firmware:
        for path in sorted(Path(firmware).glob("*.nca")):
            content_id = bytes.fromhex(path.name[:32])
            size = path.stat().st_size
            locations[STORAGE_BUILT_IN_SYSTEM].append((content_id, path, 0, size, Nca(path, keys)))
            if path.name.endswith(".cnmt.nca"):
                write_content_meta(out, STORAGE_BUILT_IN_SYSTEM, Nca(path, keys), content_id, size, path)
                count += 1
    for package in packages:
        for name, (offset, size) in container_entries(package).items():
            if not name.endswith(".nca"):
                continue
            content_id = bytes.fromhex(name[:32])
            locations[STORAGE_BUILT_IN_USER].append((content_id, Path(package), offset, size, Nca(package, keys, offset)))
            if name.endswith(".cnmt.nca"):
                meta_id, version, meta_type = write_content_meta(
                    out, STORAGE_BUILT_IN_USER, Nca(package, keys, offset), content_id, size, package)
                print(f"{Path(package).name}: {meta_id:016x} v{version} type {meta_type:#x}")
                count += 1
    # An install replaces an older version of the same content meta, as an
    # update replaces the patch a game card carries.
    for folder in Path(out).iterdir():
        newest = {}
        for meta in folder.glob("*.meta"):
            meta_id, version, meta_type, install = meta.stem.split("_")
            newest.setdefault((meta_id, meta_type, install), []).append((int(version), meta))
        for versions in newest.values():
            for _, meta in sorted(versions)[:-1]:
                meta.unlink()
                count -= 1
    for storage, entries in locations.items():
        if not entries:
            continue
        folder = Path(out) / STORAGE_NAMES[storage]
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / "contents.txt", "w", encoding="utf-8") as f:
            for content_id, path, offset, size, nca in entries:
                generation = max(nca.header[0x206], nca.header[0x220])
                f.write(f"{content_id.hex()} {offset:#x} {size:#x} {nca.rights_id.hex()} {generation} {path.resolve()}\n")
    print(f"{count} content metas written under {out}")


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
    parser.add_argument("--firmware")
    parser.add_argument("--host", help="only list modules hosting a service with this prefix")
    parser.add_argument("--extract", help="write each matching module's ExeFS files under this folder")
    parser.add_argument("--nacp", nargs=2, metavar=("NSP", "OUT"),
                        help="write the application control data (control.nacp) of an NSP to OUT")
    parser.add_argument("--exefs", nargs=2, metavar=("NSP", "OUT"),
                        help="write the ExeFS files of an NSP's Program NCA under the folder OUT")
    parser.add_argument("--romfs", nargs=2, metavar=("GAME", "OUT"),
                        help="write the RomFS image of a game's (NSP or XCI) Program NCA to OUT")
    parser.add_argument("--update", metavar="NSP",
                        help="with --romfs, apply this update's patch RomFS over the game's")
    parser.add_argument("--system-data", nargs="+", metavar=("OUT", "ID"),
                        help="write the RomFS image of each firmware system-data archive ID (hex), "
                             "or of every one for 'all', to OUT/<id>.romfs")
    parser.add_argument("--content-index", nargs="+", metavar=("OUT", "PACKAGE"),
                        help="write the firmware's content metas (with --firmware) and each package's "
                             "(NSP or XCI, as installed in BuiltInUser) under OUT, for module_host --content")
    args = parser.parse_args()
    keys = load_keys(args.keys)
    if args.content_index:
        write_content_index(args.content_index[0], args.firmware, args.content_index[1:], keys)
        return
    if args.system_data:
        if not args.firmware or len(args.system_data) < 2:
            parser.error("--system-data needs --firmware, a folder and at least one ID")
        out = Path(args.system_data[0])
        out.mkdir(parents=True, exist_ok=True)
        every = args.system_data[1:] == ["all"]
        wanted = set() if every else {int(i, 16) for i in args.system_data[1:]}
        for path in sorted(Path(args.firmware).glob("*.nca")):
            if path.name.endswith(".cnmt.nca") or not (wanted or every):
                continue
            nca = Nca(path, keys)
            if nca.content_type not in (4, 5) or not (every or nca.program_id in wanted): # Data or PublicData
                continue
            index = nca.romfs_section()
            target = out / f"{nca.program_id:016x}.romfs"
            blocks = write_romfs(lambda o, s: nca.read_section(index, o, s), nca.fs_header(index), target)
            print(f"{nca.program_id:016x}: {target.name}, {target.stat().st_size} bytes, {blocks} blocks verified")
            wanted.discard(nca.program_id)
        if wanted:
            raise SystemExit(f"not in the firmware: {', '.join(f'{i:016x}' for i in sorted(wanted))}")
        return
    if args.romfs:
        base = program_nca(args.romfs[0], keys, patch=False)
        base_index = base.romfs_section()
        if args.update:
            patch = program_nca(args.update, keys, patch=True)
            patch_index = next(i for i, _, _, fs in patch.sections if fs[4] == 4)
            section = PatchedSection(base, base_index, patch, patch_index)
            read, fs = section.read, patch.fs_header(patch_index)
            print(f"{patch.program_id:016x}: patch with {len(section.indirect)} relocations, "
                  f"{len(section.subsections)} subsections")
        else:
            read, fs = (lambda offset, size: base.read_section(base_index, offset, size)), base.fs_header(base_index)

        def report(done, total):
            print(f"\r{done >> 20} / {total >> 20} MiB", end="", file=sys.stderr, flush=True)
        blocks = write_romfs(read, fs, args.romfs[1], report)
        print(file=sys.stderr)
        print(f"{base.program_id:016x}: RomFS, {ivfc_level(fs, 5)[1]} bytes, {blocks} blocks verified")
        return
    if args.exefs:
        nca = program_nca(args.exefs[0], keys)
        out = Path(args.exefs[1])
        out.mkdir(parents=True, exist_ok=True)
        files = nca.pfs0(0)
        for file in files:
            (out / file).write_bytes(nca.read_file(0, file))
        print(f"{nca.program_id:016x}: {', '.join(sorted(files))}")
        return
    if args.nacp:
        program_id, nacp = nsp_control_nacp(args.nacp[0], keys)
        Path(args.nacp[1]).write_bytes(nacp)
        print(f"{program_id:016x}: control.nacp, {len(nacp)} bytes")
        return
    if not args.firmware:
        parser.error("--firmware is required unless --nacp, --exefs or --romfs is given")
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
