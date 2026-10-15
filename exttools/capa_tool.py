"""capa: https://github.com/mandiant/capa

pip install flare-capa
capa --update-rules   (once; downloads capa-rules to %USERPROFILE%/.capa/)
"""
from __future__ import annotations

import json
import shutil
import subprocess


def _exe() -> str | None:
    for name in ("capa", "capa.exe"):
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


def normalize(data: dict | None) -> list[dict]:
    if not data:
        return []
    out: list[dict] = []
    for rule_name, rule in (data.get("rules") or {}).items():
        meta = rule.get("meta") or {}
        out.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "scope": rule.get("scope", ""),
            "attack": meta.get("att&ck") or meta.get("attack") or [],
            "mbc": meta.get("mbc") or [],
            "addresses": [m.get("address") for m in (rule.get("matches") or [])
                          if isinstance(m, dict) and "address" in m][:20],
        })
    out.sort(key=lambda x: (x["namespace"], x["rule"]))
    return out