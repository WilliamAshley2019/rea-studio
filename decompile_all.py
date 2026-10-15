"""Decompile every procedure in a binary to one .c file per function.

  python decompile_all.py --binary "FILEPATH.EXT"

Writes reports/<stem>-src/<sha256>/<addr>_<name>.c plus index.json.
Cached: re-running on the same binary is instant (compares SHA-256).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from mcp_client import ReaClient


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _unwrap(data):
    if isinstance(data, dict):
        for k in ("normalized_result", "result"):
            if k in data:
                return data[k]
    return data


def _as_list(v):
    return v if isinstance(v, list) else []


def _as_dict(v):
    return v if isinstance(v, dict) else {}


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60] or "fn"


async def dump(client, binary: str, out_root: Path, log=print) -> Path:
    sha = sha256_of(binary)
    out = out_root / sha
    index_path = out / "index.json"
    if index_path.exists():
        log(f"Cached: {out}")
        return out

    out.mkdir(parents=True, exist_ok=True)
    await client.call_tool("open_binary", {"path": binary})

    procs = _as_list(_unwrap(await client.call_tool("list_procedures", {})))
    procs = [(str(_as_dict(p).get("address", "")), str(_as_dict(p).get("value", "")))
             for p in procs]
    procs = [(a, n) for a, n in procs if a]

    log(f"Decompiling {len(procs)} procedure(s) into {out}")
    index: list[dict] = []
    for i, (addr, name) in enumerate(procs, 1):
        if i % 25 == 0 or i == 1 or i == len(procs):
            log(f"  [{i}/{len(procs)}] {addr} {name[:40]}")
        try:
            b = _as_dict(_unwrap(await client.call_tool(
                "analyze_function", {"procedure": addr})))
        except Exception as e:
            log(f"      {addr}: {e}")
            continue
        if not b:
            continue
        fn = out / f"{addr}_{_safe(name)}.c"
        fn.write_text(b.get("pseudocode") or "// no pseudocode returned",
                      encoding="utf-8")
        index.append({"address": addr, "name": name,
                      "file": fn.name,
                      "callers": [c.get("name", "?") for c in _as_list(b.get("callers"))],
                      "callees": [c.get("name", "?") for c in _as_list(b.get("callees"))]})

    (out / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    log(f"  wrote {len(index)} .c file(s)")
    return out


async def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    out_root = Path(a.out) if a.out else (
        config.APP_DIR / "reports" / f"{Path(a.binary).stem}-src")
    cfg = config.load()
    async with ReaClient.from_config(cfg) as client:
        await dump(client, a.binary, out_root)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))