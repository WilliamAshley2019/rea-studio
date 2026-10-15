"""FLOSS: https://github.com/mandiant/flare-floss

pip install flare-floss
"""
from __future__ import annotations

import json
import shutil
import subprocess


def _exe() -> str | None:
    for name in ("floss", "floss.exe"):
        p = shutil.which(name)
        if p:
            return p
    return None


def available() -> bool:
    return _exe() is not None


def run(path: str, timeout: int = 300) -> dict | None:
    exe = _exe()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-j", path], capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        if not r.stdout.strip():
            return None
        return json.loads(r.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def normalize(data: dict | None) -> dict[str, list[str]]:
    if not data:
        return {"static": [], "stack": [], "tight": [], "decoded": []}
    return {
        "static":  [s.get("string", "") for s in data.get("strings", {}).get("static_strings", []) if s.get("string")],
        "stack":   [s.get("string", "") for s in data.get("strings", {}).get("stack_strings", []) if s.get("string")],
        "tight":   [s.get("string", "") for s in data.get("strings", {}).get("tight_strings", []) if s.get("string")],
        "decoded": [s.get("string", "") for s in data.get("strings", {}).get("decoded_strings", []) if s.get("string")],
    }