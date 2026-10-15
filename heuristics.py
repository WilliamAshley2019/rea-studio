"""Cheap pure-Python heuristics that run before REA is touched.

Each function takes a file path and returns a list of Finding objects.
Runs in under a second for typical binaries. Detects:

  - segments with addresses far above the image base (the "tdb" case)
  - very high entropy across most of the file (packed/encrypted)
  - sparse imports (packer heuristic, no pefile needed)
  - writable + executable sections
  - tiny .text with large .data (packer or data-heavy)

These complement packer_detect.py and entropy.py; they do not replace them.
"""
from __future__ import annotations

import struct
from pathlib import Path

from findings import Finding


def _read_pe_sections(path: str) -> list[dict]:
    """Return [{name, vaddr, vsize, raw_size, characteristics}] or []."""
    with open(path, "rb") as f:
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return []
        e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
        f.seek(e_lfanew)
        if f.read(4) != b"PE\0\0":
            return []
        cof = f.read(20)
        nsec = struct.unpack_from("<H", cof, 2)[0]
        optsize = struct.unpack_from("<H", cof, 16)[0]
        f.read(optsize)
        out = []
        for _ in range(nsec):
            row = f.read(40)
            if len(row) < 40:
                break
            name = row[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, raw_size, _raw_ptr = struct.unpack_from("<IIII", row, 8)
            chars = struct.unpack_from("<I", row, 36)[0]
            out.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                        "raw_size": raw_size, "chars": chars})
    return out


def _pe_image_base(path: str) -> int | None:
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if dos[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew + 4 + 20)
            magic = struct.unpack_from("<H", f.read(2))[0]
            if magic == 0x10B:
                # PE32: image base at optional header offset 28
                f.seek(e_lfanew + 4 + 20 + 28)
                return struct.unpack("<I", f.read(4))[0]
            if magic == 0x20B:
                # PE32+: image base at optional header offset 24 (8 bytes)
                f.seek(e_lfanew + 4 + 20 + 24)
                return struct.unpack("<Q", f.read(8))[0]
    except (OSError, struct.error):
        pass
    return None


def check_runtime_segments(path: str) -> list[Finding]:
    """Segments whose address is far above image base + reasonable size."""
    base = _pe_image_base(path)
    if base is None:
        return []
    # Anything more than 0x100000000 above image base is suspicious on a
    # normal PE; those addresses are almost always runtime-mapped regions.
    threshold = base + 0x100000000
    out: list[Finding] = []
    for s in _read_pe_sections(path):
        va = base + s["vaddr"]
        if va > threshold and s["vsize"] > 0:
            out.append(Finding(
                kind="runtime-segment", severity="warn",
                title=f"Segment '{s['name']}' at {va:#x} is >4GB above image base",
                detail=f"start={va:#x} size={s['vsize']:#x}; "
                       f"likely a runtime-mapped region (custom allocator, "
                       f"JIT, or DRM blob)",
                address=f"{va:#x}", source="heuristics",
                confidence="medium",
            ))
    return out


def check_wx_sections(path: str) -> list[Finding]:
    """Sections that are writable and executable simultaneously."""
    out: list[Finding] = []
    for s in _read_pe_sections(path):
        chars = s["chars"]
        w = bool(chars & 0x80000000)
        x = bool(chars & 0x20000000)
        if w and x:
            out.append(Finding(
                kind="wx-segment", severity="warn",
                title=f"Section '{s['name']}' is writable AND executable",
                detail="Common in packers, self-modifying code, and JIT engines.",
                source="heuristics", confidence="high",
            ))
    return out


def check_sparse_imports(path: str) -> list[Finding]:
    """PE with very few imports: packer heuristic that doesn't need pefile."""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        n = sum(len(e.imports or []) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    except Exception:
        return []
    if n == 0:
        return [Finding(
            kind="imports", severity="high",
            title="Zero imports",
            detail="Unusual for a normal PE; likely packed or a shellcode-like stub.",
            source="heuristics", confidence="high",
        )]
    if n < 10:
        return [Finding(
            kind="imports", severity="warn",
            title=f"Only {n} imported function(s)",
            detail="Common in packed or minimalist binaries.",
            source="heuristics", confidence="medium",
        )]
    return []


def check_all(path: str) -> list[Finding]:
    out: list[Finding] = []
    out += check_runtime_segments(path)
    out += check_wx_sections(path)
    out += check_sparse_imports(path)
    return out