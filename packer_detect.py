"""Packer / protector detection.

Three signals, in order of confidence:
  1. diec -j (if installed)
  2. PE section names with known packer signatures
  3. Heuristics on the PE (few imports + high entropy + entry point outside
     the first section + very small .text)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

try:
    import pefile
except ImportError:
    pefile = None


SECTION_SIGNS: dict[str, tuple[str, str]] = {
    "UPX0": ("UPX", "upx"), "UPX1": ("UPX", "upx"), "UPX2": ("UPX", "upx"),
    ".UPX0": ("UPX", "upx"), ".UPX1": ("UPX", "upx"), ".UPX2": ("UPX", "upx"),
    ".aspack": ("ASPack", "aspack"), ".adata": ("ASPack", "aspack"),
    ".themida": ("Themida/WinLicense", "themida"),
    ".vmp0": ("VMProtect", "vmprotect"), ".vmp1": ("VMProtect", "vmprotect"),
    ".mpress1": ("MPRESS", "mpress"), ".mpress2": ("MPRESS", "mpress"),
    "FSG!": ("FSG", "fsg"),
    "MEW": ("MEW", "mew"),
    ".petite": ("Petite", "petite"),
    ".nsp0": ("NsPack", "nspack"), ".nsp1": ("NsPack", "nspack"),
    ".enigma1": ("Enigma", "enigma"), ".enigma2": ("Enigma", "enigma"),
    ".pec1": ("PECompact", "pecompact"), ".pec2": ("PECompact", "pecompact"),
    ".packed": ("generic ('.packed' section name)", "generic"),
    ".boom": ("The Boomerang", "boom"),
}


@dataclass
class PackerVerdict:
    packed: bool = False
    confidence: str = "low"
    family: str | None = None
    signals: list[str] = field(default_factory=list)
    die_output: dict | None = None

    def summary(self) -> str:
        if not self.packed:
            return "No packer signature detected."
        head = f"Packed ({self.confidence} confidence): {self.family or 'unknown family'}"
        return head + (" -- " + "; ".join(self.signals) if self.signals else "")


def diec_available() -> str | None:
    for name in ("diec", "diec.exe"):
        p = shutil.which(name)
        if p:
            return p
    for cand in (r"C:\Tools\die\diec.exe", r"C:\Program Files\Detect It Easy\diec.exe"):
        if Path(cand).exists():
            return cand
    return None


def run_diec(path: str) -> dict | None:
    exe = diec_available()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-j", path], capture_output=True, text=True,
                           timeout=30, encoding="utf-8", errors="replace")
        if r.returncode != 0 or not r.stdout.strip():
            return None
        return json.loads(r.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def _sections_of(path: str) -> list[str]:
    if pefile is None:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return []
    names = []
    for s in pe.sections:
        raw = s.Name.rstrip(b"\x00")
        try:
            names.append(raw.decode("ascii"))
        except UnicodeDecodeError:
            names.append(raw.decode("latin-1", errors="replace"))
    return names


def _entry_section(path: str) -> tuple[str | None, bool]:
    if pefile is None:
        return (None, False)
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return (None, False)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for i, s in enumerate(pe.sections):
        start = s.VirtualAddress
        end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if start <= ep < end:
            name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            return (name, i == 0)
    return (None, False)


def _imports_count(path: str) -> int | None:
    if pefile is None:
        return None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        return sum(len(e.imports or []) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    except Exception:
        return None


def detect(path: str, run_die: bool = True) -> PackerVerdict:
    v = PackerVerdict()

    if run_die:
        die = run_diec(path)
        if die is not None:
            v.die_output = die
            found = _walk_die_for_protector(die)
            if found:
                v.packed = True
                v.confidence = "high"
                v.family = found
                v.signals.append(f"diec: {found}")

    sections = _sections_of(path)
    for s in sections:
        if s in SECTION_SIGNS:
            label, family = SECTION_SIGNS[s]
            v.packed = True
            v.confidence = "high"
            v.family = v.family or family
            v.signals.append(f"section '{s}' -> {label}")

    if not v.packed and pefile is not None:
        ep_sec, ep_is_first = _entry_section(path)
        n_imports = _imports_count(path)
        if n_imports is not None and n_imports < 10:
            v.signals.append(f"only {n_imports} imports")
        if ep_sec and not ep_is_first:
            v.signals.append(f"entry point in section '{ep_sec}' (not the first section)")
        if (n_imports is not None and n_imports < 10
                and ep_sec is not None and not ep_is_first):
            v.packed = True
            v.confidence = "medium"
            v.family = v.family or "generic (heuristic)"

    return v


def _walk_die_for_protector(node) -> str | None:
    if isinstance(node, dict):
        for key in ("packer", "protector", "Packer", "Protector"):
            if key in node and node[key]:
                return str(node[key])
        for v in node.values():
            hit = _walk_die_for_protector(v)
            if hit:
                return hit
    elif isinstance(node, list):
        for item in node:
            hit = _walk_die_for_protector(item)
            if hit:
                return hit
    return None