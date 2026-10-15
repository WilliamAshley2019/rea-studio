"""Optional external analysers.

Each module exposes:
    available() -> bool
    run(path: str) -> dict | None

Wrappers must never raise: a missing tool or a bad sample is `None`.
"""
from __future__ import annotations

WRAPPERS: dict[str, tuple[str, str]] = {
    "pdb":   ("exttools.pdb_tool",   "PDB fetch (Microsoft symbol server)"),
    "capa":  ("exttools.capa_tool",  "capa (MITRE capability detection)"),
    "floss": ("exttools.floss_tool", "FLOSS (obfuscated strings)"),
    "yara":  ("exttools.yara_tool",  "YARA (rule matching)"),
    "pefile":("exttools.pefile_tool","pefile (headers, imports)"),
}


def load(name: str):
    import importlib
    mod_name, _ = WRAPPERS[name]
    return importlib.import_module(mod_name)


def available_tools() -> dict[str, bool]:
    out = {}
    for name in WRAPPERS:
        try:
            mod = load(name)
            out[name] = bool(mod.available())
        except Exception:
            out[name] = False
    return out