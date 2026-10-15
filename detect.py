"""File-type detection from magic bytes.

Supersedes detect_file_type.ps1. Two ordering fixes:
  - Mach-O fat (CA FE BA BE) is checked before Java .class (also CA FE BA BE).
  - The 8-byte wasm magic is checked before the 4-byte one.

Reads only the first 4 KiB unless a format needs more (PE, ELF).
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

KIND_PE = "pe"
KIND_PE_MANAGED = "pe-managed"
KIND_DOS_MZ = "dos-mz"
KIND_DOS_COM = "dos-com"
KIND_ELF = "elf"
KIND_MACHO = "macho"
KIND_MACHO_FAT = "macho-fat"
KIND_JAVA_CLASS = "java-class"
KIND_ARCHIVE = "archive"
KIND_GZIP = "gzip"
KIND_BZIP2 = "bzip2"
KIND_XZ = "xz"
KIND_7Z = "7z"
KIND_RAR = "rar"
KIND_CAB = "cab"
KIND_MSI = "msi"
KIND_TAR = "tar"
KIND_SQLITE = "sqlite"
KIND_PDF = "pdf"
KIND_OLE2 = "ole2"
KIND_RTF = "rtf"
KIND_PNG = "png"
KIND_JPEG = "jpeg"
KIND_GIF = "gif"
KIND_BMP = "bmp"
KIND_TIFF = "tiff"
KIND_RIFF = "riff"
KIND_FLAC = "flac"
KIND_MP3 = "mp3"
KIND_MP4 = "mp4"
KIND_MKV = "mkv"
KIND_OGG = "ogg"
KIND_MPEG_PS = "mpeg-ps"
KIND_PEM = "pem"
KIND_DER = "der"
KIND_OPENSSL_SALTED = "openssl-salted"
KIND_BITCOIN = "bitcoin"
KIND_WASM = "wasm"
KIND_SCRIPT = "script"
KIND_JSON = "json"
KIND_UNKNOWN = "unknown"

NON_NATIVE_KINDS = {
    KIND_ARCHIVE, KIND_GZIP, KIND_BZIP2, KIND_XZ, KIND_7Z, KIND_RAR,
    KIND_CAB, KIND_MSI, KIND_TAR, KIND_SQLITE, KIND_PDF, KIND_OLE2, KIND_RTF,
    KIND_PNG, KIND_JPEG, KIND_GIF, KIND_BMP, KIND_TIFF, KIND_RIFF,
    KIND_FLAC, KIND_MP3, KIND_MP4, KIND_MKV, KIND_OGG, KIND_MPEG_PS,
    KIND_PEM, KIND_DER, KIND_OPENSSL_SALTED, KIND_BITCOIN,
    KIND_PE_MANAGED, KIND_JAVA_CLASS, KIND_WASM,
}

PE_MACHINES = {
    0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64",
    0x01C0: "arm", 0x01C4: "arm", 0x0200: "ia64",
    0x01F0: "powerpc", 0x5032: "riscv32", 0x5064: "riscv64",
}
ELF_MACHINES = {
    0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "arm64",
    0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0xF3: "riscv",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("macho", 32, "big"),
    b"\xfe\xed\xfa\xcf": ("macho", 64, "big"),
    b"\xce\xfa\xed\xfe": ("macho", 32, "little"),
    b"\xcf\xfa\xed\xfe": ("macho", 64, "little"),
}

# Mach-O CPU types, from <mach/machine.h>. Used to disambiguate a Mach-O
# fat binary (CA FE BA BE) from a Java .class (which shares the magic).
MACHO_CPUTYPES = {
    0x00000007,  # x86
    0x01000007,  # x86_64
    0x0000000C,  # ARM
    0x0100000C,  # ARM64
    0x00000012,  # PowerPC
    0x01000012,  # PowerPC64
    0x0000000A,  # MC680x0
}

PACKER_SECTION_PREFIXES = ("UPX", ".UPX", ".aspack", ".ASPack", ".themida",
                           ".vmp", ".mpress", "FSG!", "MEW", ".petite", ".nsp",
                           ".enigma", ".pec", ".boom", ".packed")


@dataclass
class Detection:
    path: str
    size: int
    kind: str
    label: str
    open_args: dict = field(default_factory=dict)
    native: bool = True
    managed: bool = False
    notes: list[str] = field(default_factory=list)
    pe_machine: str | None = None
    pe_bits: int | None = None
    pe_is_dll: bool | None = None
    pe_sections: list[str] = field(default_factory=list)
    pe_is_packed_by_section: bool = False
    elf_bits: int | None = None
    elf_machine: str | None = None


def _head(path: str, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _match(data: bytes, off: int, sig: bytes) -> bool:
    return len(data) >= off + len(sig) and data[off:off + len(sig)] == sig


def _ascii_safe(data: bytes, off: int, n: int) -> str:
    end = min(off + n, len(data))
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data[off:end])


def _parse_pe(path: str, size: int) -> dict | None:
    with open(path, "rb") as f:
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 24 > size:
            return {"dos_only": True}
        f.seek(e_lfanew)
        if f.read(4) != b"PE\0\0":
            return {"dos_only": True}
        cof = f.read(20)
        machine, nsec, _ts, _ptr, _nsym, optsize, chars = struct.unpack("<HHIIIHH", cof)
        optsize = min(optsize, 4096)
        opt = f.read(optsize)
        magic = struct.unpack_from("<H", opt, 0)[0] if len(opt) >= 2 else 0
        bits = 32 if magic == 0x10B else 64 if magic == 0x20B else None
        dd_off = 96 if bits == 32 else 112 if bits == 64 else None
        managed = False
        if dd_off is not None and len(opt) >= dd_off + 8 * 15:
            rva, sz = struct.unpack_from("<II", opt, dd_off + 8 * 14)
            managed = bool(rva and sz)
        sections: list[str] = []
        sec_off = e_lfanew + 4 + 20 + optsize
        try:
            f.seek(sec_off)
            for _ in range(nsec):
                row = f.read(40)
                if len(row) < 40:
                    break
                name = row[:8].rstrip(b"\x00").decode("ascii", errors="replace")
                sections.append(name)
        except OSError:
            pass
    return {
        "machine": machine, "bits": bits, "dll": bool(chars & 0x2000),
        "managed": managed, "sections": sections,
    }


def _parse_elf(head: bytes) -> dict:
    bits = 32 if head[4] == 1 else 64
    little = head[5] != 2
    endian = "<" if little else ">"
    machine = struct.unpack_from(f"{endian}H", head, 18)[0]
    return {"bits": bits, "machine": machine, "little": little}


def detect(path: str, raw_arch: str | None = None, raw_entry: str | None = None) -> Detection:
    p = os.path.abspath(path.strip().strip('"'))
    size = os.path.getsize(p)
    if size < 4:
        return Detection(p, size, KIND_UNKNOWN, "File too small to identify")

    head = _head(p, 4096)
    ext = os.path.splitext(p)[1].lower()

    if head[:2] == b"MZ":
        pe = _parse_pe(p, size)
        if pe and not pe.get("dos_only"):
            what = "DLL" if pe["dll"] else "EXE"
            bits = pe["bits"] or "?"
            mach = PE_MACHINES.get(pe["machine"], f"0x{pe['machine']:04X}")
            hits = [s for s in pe["sections"] if s.startswith(PACKER_SECTION_PREFIXES)]
            kind = KIND_PE_MANAGED if pe["managed"] else KIND_PE
            label = f"Windows PE {what} {bits}-bit {mach}"
            if pe["managed"]:
                label = ".NET " + label
            notes: list[str] = []
            if pe["managed"]:
                notes.append("Managed (.NET) assembly: native disassembly is not useful; "
                             "the managed inspectors run instead.")
            if hits:
                notes.append(f"Packer-style section name(s) present: {', '.join(hits)}")
            return Detection(
                p, size, kind, label,
                native=not pe["managed"], managed=pe["managed"], notes=notes,
                pe_machine=mach, pe_bits=bits, pe_is_dll=pe["dll"],
                pe_sections=pe["sections"], pe_is_packed_by_section=bool(hits),
            )
        return Detection(p, size, KIND_DOS_MZ, "DOS MZ executable (no PE header)",
                         notes=["Header-based detection only; Ghidra may need an explicit processor."])

    if head[:4] == b"\x7fELF":
        e = _parse_elf(head)
        mach = ELF_MACHINES.get(e["machine"], f"0x{e['machine']:04X}")
        return Detection(p, size, KIND_ELF, f"ELF {e['bits']}-bit {mach}",
                         elf_bits=e["bits"], elf_machine=mach)

    if _match(head, 0, b"\xca\xfe\xba\xbe"):
        # Mach-O fat and Java .class share the CA FE BA BE magic.
        # Disambiguate on the first fat_arch's cputype.
        if len(head) >= 12:
            nfat = struct.unpack_from(">I", head, 4)[0]
            cputype = struct.unpack_from(">I", head, 8)[0]
            if 1 <= nfat <= 32 and cputype in MACHO_CPUTYPES:
                return Detection(p, size, KIND_MACHO_FAT,
                                 f"Mach-O fat binary ({nfat} archs)", native=True)
        return Detection(p, size, KIND_JAVA_CLASS, "Java .class", native=False)

    for magic, (kind, bits, endian) in MACHO_MAGICS.items():
        if _match(head, 0, magic):
            return Detection(p, size, kind, f"Mach-O {bits}-bit {endian}-endian", native=True)

    if ext == ".com" and 1 <= size <= 65280:
        return Detection(p, size, KIND_DOS_COM, "DOS COM (headerless)",
                         {"format": "dos-com"})

    if head[:2] == b"#!":
        line = _ascii_safe(head, 0, min(120, len(head)))
        return Detection(p, size, KIND_SCRIPT, f"Script: {line}", native=False)

    if _match(head, 0, b"PK\x03\x04") or _match(head, 0, b"PK\x05\x06") or _match(head, 0, b"PK\x07\x08"):
        return Detection(p, size, KIND_ARCHIVE, "ZIP archive (or JAR/APK/DOCX/XLSX)", native=False)
    if _match(head, 0, b"\x1f\x8b"):
        return Detection(p, size, KIND_GZIP, "GZip stream", native=False)
    if _match(head, 0, b"BZh"):
        return Detection(p, size, KIND_BZIP2, "BZip2 archive", native=False)
    if _match(head, 0, b"\xfd7zXZ\x00"):
        return Detection(p, size, KIND_XZ, "XZ compressed stream", native=False)
    if _match(head, 0, b"7z\xbc\xaf\x27\x1c"):
        return Detection(p, size, KIND_7Z, "7-Zip archive", native=False)
    if _match(head, 0, b"Rar!\x1a\x07\x01\x00"):
        return Detection(p, size, KIND_RAR, "RAR archive v5+", native=False)
    if _match(head, 0, b"Rar!\x1a\x07\x00"):
        return Detection(p, size, KIND_RAR, "RAR archive v1.5-4.x", native=False)
    if _match(head, 0, b"MSCF"):
        return Detection(p, size, KIND_CAB, "Microsoft CAB archive", native=False)
    if _match(head, 0, b"\xd0\xcf\x11\xe0"):
        return Detection(p, size, KIND_OLE2, "OLE2 compound document (DOC/XLS/PPT/MSI)", native=False)
    if _match(head, 0, b"\x28\x00\x00\x00") and _match(head, 4, b"\x00" * 8):
        return Detection(p, size, KIND_MSI, "Windows Installer (MSI) or CAB", native=False)
    if _match(head, 257, b"ustar") or _match(head, 0, b"ustar"):
        return Detection(p, size, KIND_TAR, "tar archive", native=False)

    if _match(head, 0x438, b"\x53\xef"):
        return Detection(p, size, KIND_UNKNOWN, "ext2/ext3/ext4 filesystem image", native=False)
    if _match(head, 3, b"NTFS    "):
        return Detection(p, size, KIND_UNKNOWN, "NTFS filesystem image", native=False)
    if _match(head, 3, b"MSDOS"):
        return Detection(p, size, KIND_UNKNOWN, "FAT12/16 filesystem image", native=False)
    if _match(head, 3, b"FAT32"):
        return Detection(p, size, KIND_UNKNOWN, "FAT32 filesystem image", native=False)
    if _match(head, 0, b"SQLite format 3\x00"):
        return Detection(p, size, KIND_SQLITE, "SQLite 3 database", native=False)

    if _match(head, 0, b"%PDF"):
        return Detection(p, size, KIND_PDF, "PDF document", native=False)
    if _match(head, 0, b"{\\rtf"):
        return Detection(p, size, KIND_RTF, "RTF document", native=False)

    if _match(head, 0, b"\x89PNG\r\n\x1a\n"):
        return Detection(p, size, KIND_PNG, "PNG image", native=False)
    if _match(head, 0, b"\xff\xd8\xff"):
        return Detection(p, size, KIND_JPEG, "JPEG image", native=False)
    if _match(head, 0, b"GIF8"):
        return Detection(p, size, KIND_GIF, "GIF image", native=False)
    if _match(head, 0, b"BM"):
        return Detection(p, size, KIND_BMP, "BMP image", native=False)
    if _match(head, 0, b"II*\x00") or _match(head, 0, b"MM\x00*"):
        return Detection(p, size, KIND_TIFF, "TIFF image", native=False)
    if _match(head, 0, b"RIFF"):
        sub = _ascii_safe(head, 8, 4)
        return Detection(p, size, KIND_RIFF, f"RIFF container ({sub})", native=False)
    if _match(head, 0, b"fLaC"):
        return Detection(p, size, KIND_FLAC, "FLAC audio", native=False)
    if _match(head, 0, b"ID3") or _match(head, 0, b"\xff\xfb"):
        return Detection(p, size, KIND_MP3, "MP3 audio", native=False)
    if _match(head, 4, b"ftyp"):
        return Detection(p, size, KIND_MP4, "ISO Base Media (MP4/MOV/M4A)", native=False)
    if _match(head, 0, b"\x1a\x45\xdf\xa3"):
        return Detection(p, size, KIND_MKV, "Matroska / WebM", native=False)
    if _match(head, 0, b"OggS"):
        return Detection(p, size, KIND_OGG, "Ogg container", native=False)
    if _match(head, 0, b"\x00\x00\x01\xba") or _match(head, 0, b"\x00\x00\x01\xb3"):
        return Detection(p, size, KIND_MPEG_PS, "MPEG program stream", native=False)

    if _match(head, 0, b"-----BEGIN"):
        return Detection(p, size, KIND_PEM, "PEM-encoded crypto", native=False)
    if _match(head, 0, b"0\x82"):
        return Detection(p, size, KIND_DER, "DER-encoded ASN.1", native=False)
    if _match(head, 0, b"Salted__"):
        return Detection(p, size, KIND_OPENSSL_SALTED, "OpenSSL salted encrypted data", native=False)
    if _match(head, 0, b"\xf9\xbe\xb4\xd9"):
        return Detection(p, size, KIND_BITCOIN, "Bitcoin blockchain data", native=False)

    if _match(head, 0, b"\x00asm\x01\x00\x00\x00"):
        return Detection(p, size, KIND_WASM, "WebAssembly binary v1 (.wasm)", native=False)
    if _match(head, 0, b"\x00asm"):
        return Detection(p, size, KIND_WASM, "WebAssembly binary (.wasm)", native=False)

    if head[:1] in (b"{", b"["):
        try:
            import json
            json.loads(head[:2048].decode("utf-8", errors="replace")
                       .rsplit("}", 1)[0] + "}" if head[:1] == b"{" else "[]")
            return Detection(p, size, KIND_JSON, "JSON text", native=False)
        except Exception:
            pass

    if raw_arch and raw_entry:
        return Detection(p, size, KIND_UNKNOWN,
                         f"Raw binary as {raw_arch} @ {raw_entry}",
                         {"format": "raw-binary", "architecture": raw_arch,
                          "entry_point": raw_entry})

    return Detection(p, size, KIND_UNKNOWN, "Unrecognized format",
                     notes=["REA will try its own detection. If it refuses, this is probably "
                            "a headerless dump: supply the CPU (x86, x86_64, arm, arm64, 6502) "
                            "and the load/entry address."])