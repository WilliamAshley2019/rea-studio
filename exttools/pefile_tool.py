"""pefile: pip install pefile

Header / import / export / resource summary. Fast (no disassembly).
"""
from __future__ import annotations

from pathlib import Path

try:
    import pefile
except ImportError:
    pefile = None


def available() -> bool:
    return pefile is not None


def run(path: str) -> dict | None:
    if pefile is None:
        return None
    if Path(path).suffix.lower() not in (".exe", ".dll", ".sys", ".ocx", ".drv", ".cpl", ".scr"):
        try:
            with open(path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
        except OSError:
            return None
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception:
        return None

    out: dict = {
        "machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem,
                                               hex(pe.OPTIONAL_HEADER.Subsystem)),
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "sections": [
            {"name": s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
             "vaddr": hex(s.VirtualAddress),
             "vsize": s.Misc_VirtualSize,
             "raw_size": s.SizeOfRawData,
             "characteristics": hex(s.Characteristics)}
            for s in pe.sections
        ],
    }

    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("ascii", errors="replace")
        imports[dll] = []
        for imp in entry.imports or []:
            imports[dll].append(imp.name.decode("ascii", errors="replace") if imp.name else f"ordinal_{imp.ordinal}")
    out["imports"] = imports

    exports: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXPORT", []) or []:
        for exp in entry.symbols or []:
            if exp.name:
                exports.append(exp.name.decode("ascii", errors="replace"))
    out["exports"] = exports

    out["resources"] = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            name = pefile.RESOURCE_TYPE.get(t.struct.Id, f"type_{t.struct.Id}")
            for sub in t.directory.entries:
                out["resources"].append({
                    "type": name,
                    "id": sub.struct.Id,
                    "size": getattr(sub.directory.entries[0].data.struct, "Size", 0)
                            if sub.directory.entries else 0,
                })
    return out