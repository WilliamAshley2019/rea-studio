"""SHA-256-keyed cache for REA tool results.

Usage:
    import cache
    c = cache.Cache(binary_path, "xrefs")
    key = c.key({"address": "0x140001000"})
    val = c.get(key)
    if val is None:
        val = (await client.call_tool("xrefs", {"address": "0x140001000"})).data
        c.put(key, val)

Cache layout:
    %LOCALAPPDATA%\\rea-studio\\cache\\<sha256>\\<tool>\\<argsha>.json
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _default_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "rea-studio" / "cache"
    return Path.home() / ".rea-studio" / "cache"


CACHE_ROOT = _default_root()


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def arg_hash(args: dict) -> str:
    """Deterministic hash of a tool call's arguments."""
    blob = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:24]


class Cache:
    def __init__(self, binary: str, tool: str, root: Path = CACHE_ROOT):
        self.sha = sha256_of_file(binary)
        self.tool = tool
        self.dir = root / self.sha / tool
        self.dir.mkdir(parents=True, exist_ok=True)

    def key(self, args: dict) -> Path:
        return self.dir / f"{arg_hash(args)}.json"

    def get(self, key: Path) -> Any | None:
        if not key.exists():
            return None
        try:
            return json.loads(key.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def put(self, key: Path, value: Any) -> None:
        try:
            key.write_text(json.dumps(value, default=str), encoding="utf-8")
        except OSError:
            pass

    def clear(self) -> int:
        n = 0
        for f in self.dir.glob("*.json"):
            try:
                f.unlink()
                n += 1
            except OSError:
                pass
        return n

    def stats(self) -> dict:
        files = list(self.dir.glob("*.json"))
        total = sum(f.stat().st_size for f in files)
        return {"tool": self.tool, "entries": len(files), "bytes": total}