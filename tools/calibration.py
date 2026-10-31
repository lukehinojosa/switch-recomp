"""Write a blank calibration image (PRODINFO, "CAL0") for the host.

The settings sysmodule reads a console's calibration data from BIS
partition 27 (module_host --calibration serves the image). A host has no
calibration of its own, so this writes one with only what a fresh image
needs: the header, the body's SHA-256, a serial number and the CRC16 that
ends each block settings checks. Everything else in the body is zero.

Usage: calibration.py <out.bin> [--serial XAW00000000000]
"""
import argparse
import hashlib
import struct
from pathlib import Path

SIZE = 0x8000          # header and body
BODY = 0x40            # the body follows the 0x40-byte header
SERIAL = 0x250         # serial number, 0x18 bytes, NUL-padded

# The blocks settings (fw 23.0.1) checks, as (offset, size): each ends in
# a CRC16 of the bytes before it.
BLOCKS = [
    (0x0040, 0x20), (0x0080, 0x190), (0x0210, 0x8), (0x0220, 0x8), (0x0230, 0x8),
    (0x0238, 0x8), (0x0240, 0x8), (0x0248, 0x8), (0x0250, 0x20), (0x0440, 0x40),
    (0x0480, 0x190), (0x09B0, 0x120), (0x0AD0, 0x10), (0x2320, 0x120), (0x2860, 0x230),
    (0x2A90, 0x250), (0x2CE0, 0x20), (0x2D00, 0x810), (0x3510, 0x10), (0x3520, 0x60),
    (0x3580, 0x20), (0x35A0, 0x80), (0x3620, 0x50), (0x3670, 0x30), (0x36A0, 0xA0),
    (0x3740, 0x10), (0x3750, 0x10), (0x3760, 0x10), (0x3770, 0x60), (0x3890, 0x250),
    (0x3AE0, 0x140), (0x3C20, 0x140), (0x3D60, 0x10), (0x3D70, 0x250), (0x3FC0, 0x250),
    (0x4210, 0x10), (0x4220, 0x10), (0x4230, 0x10), (0x4240, 0x10), (0x4250, 0x10),
    (0x4260, 0x10), (0x4270, 0x10), (0x4280, 0x20), (0x42A0, 0x10), (0x42B0, 0x10),
    (0x42C0, 0x20), (0x42E0, 0x10), (0x42F0, 0x10), (0x4300, 0x10), (0x4310, 0x10),
    (0x4330, 0x10), (0x4340, 0x10),
]


def crc16(data):
    """Nintendo's CRC16: the reflected 0xA001 polynomial from 0x55AA, a nibble at a time."""
    table = [0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
             0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400]
    crc = 0x55AA
    for byte in data:
        crc = table[crc & 0xF] ^ (crc >> 4) ^ table[byte & 0xF]
        crc = table[crc & 0xF] ^ (crc >> 4) ^ table[byte >> 4]
    return crc


def main():
    parser = argparse.ArgumentParser(description="Write a blank CAL0 calibration image.")
    parser.add_argument("out")
    parser.add_argument("--serial", default="XAW00000000000",
                        help="the serial number set:sys GetSerialNumber reports (at most 23 characters)")
    args = parser.parse_args()
    serial = args.serial.encode("ascii")
    if len(serial) >= 0x18:
        parser.error("the serial number takes at most 23 characters")

    image = bytearray(SIZE)
    image[SERIAL:SERIAL + len(serial)] = serial
    for offset, size in BLOCKS:
        struct.pack_into("<H", image, offset + size - 2, crc16(image[offset:offset + size - 2]))
    # Header: magic, version, body size, model, update count, then the
    # body's SHA-256 at 0x20.
    struct.pack_into("<4sIIHH", image, 0, b"CAL0", 7, SIZE - BODY, 1, 0)
    image[0x20:0x40] = hashlib.sha256(image[BODY:]).digest()
    Path(args.out).write_bytes(image)
    print(f"{args.out}: CAL0, {SIZE} bytes, serial {args.serial}")


if __name__ == "__main__":
    main()
