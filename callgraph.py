"""Build a call graph from a binary already open in REA.

  python callgraph.py --binary "FILE PATH.EXE"

Writes reports/<stem>-callgraph/<sha256>.json with:
  {"sha256": ..., "procedures": [...], "callers": {addr: [caller_addr, ...]},
   "callees": {addr: [callee_addr, ...]}}

Subsequent runs read from the cache. To force a rebuild, delete the file or
pass --rebuild.

This is slow the first time (one xrefs call per procedure). On a
852-function binary: 5-10 minutes. Cached runs: < 1 second.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
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


async def build(client, binary: str, out_dir: Path, log=print) -> dict:
    # 1. Open (fast if cached).
    log(f"[1/4] open_binary {binary}")
    await client.call_tool("open_binary", {"path": binary})

    # 2. List procedures.
    log(f"[2/4] list_procedures")
    procs_raw = _unwrap(await client.call_tool("list_procedures", {}))
    procs = [(str(_as_dict(p).get("address", "")), str(_as_dict(p).get("value", "")))
             for p in _as_list(procs_raw)]
    procs = [(a, n) for a, n in procs if a]
    log(f"      {len(procs)} procedure(s)")

    # 3. For each, get xrefs (callers).
    log(f"[3/4] xrefs for each procedure (slow)")
    callers: dict[str, list[str]] = {}
    for i, (addr, name) in enumerate(procs, 1):
        if i % 50 == 0 or i == 1 or i == len(procs):
            log(f"      [{i}/{len(procs)}] {addr} {name[:40]}")
        try:
            xr = _unwrap(await client.call_tool("xrefs", {"address": addr}))
        except Exception:
            continue
        callers[addr] = [x for x in _as_list(xr) if isinstance(x, str)]

    # 4. Invert to callees.
    log(f"[4/4] inverting to callees")
    callees: dict[str, list[str]] = {a: [] for a, _ in procs}
    for callee_addr, caller_addrs in callers.items():
        for caller in caller_addrs:
            callees.setdefault(caller, []).append(callee_addr)

    graph = {
        "binary": binary,
        "sha256": sha256_of(binary),
        "procedures": [{"address": a, "name": n} for a, n in procs],
        "callers": callers,
        "callees": callees,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{graph['sha256']}.json").write_text(
        json.dumps(graph, indent=2, default=str), encoding="utf-8")
    log(f"      written {out_dir / (graph['sha256'] + '.json')}")
    return graph


def load_cached(binary: str, out_dir: Path) -> dict | None:
    p = out_dir / f"{sha256_of(binary)}.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Query helpers (usable from other scripts)
# ---------------------------------------------------------------------------
def callers_of(graph: dict, addr: str, depth: int = 1) -> set[str]:
    """Return every address that calls `addr`, up to `depth` hops."""
    seen: set[str] = set()
    frontier = {addr}
    for _ in range(depth):
        nxt: set[str] = set()
        for a in frontier:
            for c in graph.get("callers", {}).get(a, []):
                if c not in seen:
                    seen.add(c)
                    nxt.add(c)
        frontier = nxt
        if not frontier:
            break
    return seen


def callees_of(graph: dict, addr: str, depth: int = 1) -> set[str]:
    seen: set[str] = set()
    frontier = {addr}
    for _ in range(depth):
        nxt: set[str] = set()
        for a in frontier:
            for c in graph.get("callees", {}).get(a, []):
                if c not in seen:
                    seen.add(c)
                    nxt.add(c)
        frontier = nxt
        if not frontier:
            break
    return seen


def name_of(graph: dict, addr: str) -> str:
    for p in graph.get("procedures", []):
        if p.get("address") == addr:
            return p.get("name", "?")
    return "?"


async def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", default=None,
                    help="output dir (default: reports/<stem>-callgraph)")
    ap.add_argument("--rebuild", action="store_true")
    a = ap.parse_args()

    out = Path(a.out) if a.out else (
        config.APP_DIR / "reports" / f"{Path(a.binary).stem}-callgraph")

    if not a.rebuild:
        cached = load_cached(a.binary, out)
        if cached:
            print(f"Cached: {out / (cached['sha256'] + '.json')}")
            print(f"  {len(cached.get('procedures', []))} procedures")
            return 0

    cfg = config.load()
    async with ReaClient.from_config(cfg) as client:
        await build(client, a.binary, out)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))