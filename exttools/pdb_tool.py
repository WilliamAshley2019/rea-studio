"""Wrapper for fetch_pdb. Returns a dict the pipeline absorbs as findings."""
from __future__ import annotations

from pathlib import Path

import fetch_pdb


def available() -> bool:
    return True


def run(path: str, cache_dir: str | Path | None = None, timeout: int = 30) -> dict | None:
    try:
        info = fetch_pdb.fetch(path, cache_dir=cache_dir or fetch_pdb.DEFAULT_CACHE,
                               timeout=timeout)
    except Exception:
        return None
    if info is None:
        return {"available": False,
                "reason": "no CodeView RSDS debug record in the PE"}
    return {
        "available": bool(info.cached),
        "sym_name": info.sym_name,
        "guid": info.guid,
        "age": info.age,
        "symbol_url": info.symbol_url,
        "cached": info.cached,
        "reason": None if info.cached else "download failed (network/TLS)",
    }


def normalize(data: dict | None) -> dict:
    if not data:
        return {"available": False, "reason": "not attempted"}
    return {
        "available": bool(data.get("available")),
        "sym_name": data.get("sym_name"),
        "guid": data.get("guid"),
        "age": data.get("age"),
        "cached": data.get("cached"),
        "reason": data.get("reason"),
    }