"""Builders for tiny synthetic binaries. Data only; never executed."""

from __future__ import annotations

import struct


def build_minimal_pe(
    *,
    section_name: bytes = b".text",
    section_flags: int = 0x60000020,
    timestamp: int = 1_700_000_000,
    raw: bytes | None = None,
    overlay: bytes = b"",
) -> bytes:
    """Return a structurally valid PE32 image with a single section and no imports."""
    raw = raw if raw is not None else b"\x90" * 0x200
    raw = raw.ljust(0x200, b"\x00")
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x102)
    opt = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "HH" + "I" * 6,
        0x10B, 1, 0,
        0x200, 0, 0, 0x1000, 0x1000, 0x1000,  # code/data sizes, entry point, base of code/data
        0x400000, 0x1000, 0x200,  # image base, section/file alignment
        4, 0, 0, 0, 4, 0,  # OS / image / subsystem versions
        0, 0x2000, 0x200, 0,  # win32 version, size of image, size of headers, checksum
        3, 0,  # subsystem, dll characteristics
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,  # stack/heap, loader flags, rva count
    )
    opt += b"\x00" * (0xE0 - len(opt))
    sect = struct.pack(
        "<8sIIIIIIHHI", section_name.ljust(8, b"\x00"), len(raw), 0x1000, len(raw), 0x200, 0, 0, 0, 0, section_flags
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + sect
    return headers.ljust(0x200, b"\x00") + raw + overlay
