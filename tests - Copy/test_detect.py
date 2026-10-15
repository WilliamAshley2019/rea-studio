"""Detector tests. Generate each fixture on the fly; nothing committed."""
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import detect


def write(tmp: Path, name: str, data: bytes) -> str:
    p = tmp / name
    p.write_bytes(data)
    return str(p)


def minimal_pe(bits: int = 64, managed: bool = False, sections=(".text", ".rdata")) -> bytes:
    e_lfanew = 0x80
    optsize = 0xF0 if bits == 64 else 0xE0
    magic = 0x20B if bits == 64 else 0x10B
    machine = 0x8664 if bits == 64 else 0x14C
    nsec = len(sections)
    dos = bytearray(e_lfanew)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    cof = struct.pack("<4sHHIIIHH", b"PE\x00\x00", machine, nsec, 0, 0, 0, optsize, 0x0022)
    opt = bytearray(optsize)
    struct.pack_into("<H", opt, 0, magic)
    dd_off = 112 if bits == 64 else 96
    if managed:
        struct.pack_into("<II", opt, dd_off + 8 * 14, 0x2000, 0x48)
    sec = bytearray()
    for s in sections:
        nm = s.encode("ascii")[:8].ljust(8, b"\x00")
        sec += struct.pack("<8sIIIIIIHHI", nm, 0, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)
    return bytes(dos) + cof + bytes(opt) + bytes(sec)


def test_pe64():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "a.exe", minimal_pe(64))
        d = detect.detect(p)
        assert d.kind == detect.KIND_PE
        assert d.pe_bits == 64
        assert d.pe_machine == "x86_64"
        assert d.pe_is_dll is False


def test_pe32_dll():
    with tempfile.TemporaryDirectory() as td:
        data = bytearray(minimal_pe(32))
        e_lfanew = 0x80
        chars_off = e_lfanew + 4 + 18
        struct.pack_into("<H", data, chars_off, 0x2000 | 0x0022)
        p = write(Path(td), "a.dll", bytes(data))
        d = detect.detect(p)
        assert d.kind == detect.KIND_PE
        assert d.pe_is_dll is True


def test_managed():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "a.dll", minimal_pe(32, managed=True))
        d = detect.detect(p)
        assert d.kind == detect.KIND_PE_MANAGED
        assert d.managed is True
        assert d.native is False


def test_dos_mz():
    with tempfile.TemporaryDirectory() as td:
        dos = b"MZ" + b"\x00" * 62
        p = write(Path(td), "castle.exe", dos)
        d = detect.detect(p)
        assert d.kind == detect.KIND_DOS_MZ


def test_dos_com():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "tiny.com", b"\xB4\x09\xBA\x00\x01\xCD\x21")
        d = detect.detect(p)
        assert d.kind == detect.KIND_DOS_COM
        assert d.open_args.get("format") == "dos-com"


def test_elf64():
    with tempfile.TemporaryDirectory() as td:
        # e_ident (7 bytes) + 9 bytes padding + e_type (2) + e_machine (2).
        # e_machine is at offset 18 per the ELF spec.
        head = (b"\x7fELF\x02\x01\x01"      # magic + ELF64 + LE
                + b"\x00" * 9                # e_ident padding
                + b"\x00\x00"                # e_type = 0 (NONE)
                + struct.pack("<H", 0x3E))   # e_machine = x86_64
        p = write(Path(td), "a.elf", head + b"\x00" * 128)
        d = detect.detect(p)
        assert d.kind == detect.KIND_ELF
        assert d.elf_bits == 64
        assert d.elf_machine == "x86_64"


def test_macho64_little():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "a.macho", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
        d = detect.detect(p)
        assert d.kind == detect.KIND_MACHO


def test_macho_fat_vs_java():
    with tempfile.TemporaryDirectory() as td:
        # Fat Mach-O with two real architectures. fat_arch[0].cputype must
        # be a known Mach-O CPU for the detector to accept it as fat.
        fat = (b"\xca\xfe\xba\xbe"
               + struct.pack(">I", 2)                                      # nfat_arch = 2
               + struct.pack(">IIIII", 0x01000007, 3, 0x1000, 0x2000, 12)  # x86_64 arch
               + struct.pack(">IIIII", 0x0100000C, 0, 0x3000, 0x2000, 12)  # arm64 arch
               + b"\x00" * 128)
        p1 = write(Path(td), "fat.macho", fat)
        assert detect.detect(p1).kind == detect.KIND_MACHO_FAT

        # Java class: magic + minor (0) + major (52 = Java 8).
        p2 = write(Path(td), "X.class",
                   b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + b"\x00" * 64)
        assert detect.detect(p2).kind == detect.KIND_JAVA_CLASS


def test_zip():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "a.zip", b"PK\x03\x04" + b"\x00" * 32)
        d = detect.detect(p)
        assert d.kind == detect.KIND_ARCHIVE
        assert d.native is False


def test_wasm_8byte_before_4byte():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "a.wasm", b"\x00asm\x01\x00\x00\x00" + b"\x00" * 32)
        d = detect.detect(p)
        assert d.kind == detect.KIND_WASM
        assert "v1" in d.label


def test_shebang():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "run.py", b"#!/usr/bin/env python3\nprint(1)\n")
        d = detect.detect(p)
        assert d.kind == detect.KIND_SCRIPT


def test_tiny_file():
    with tempfile.TemporaryDirectory() as td:
        p = write(Path(td), "x", b"\x01")
        d = detect.detect(p)
        assert d.kind == detect.KIND_UNKNOWN


if __name__ == "__main__":
    import traceback
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                fails += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    sys.exit(1 if fails else 0)