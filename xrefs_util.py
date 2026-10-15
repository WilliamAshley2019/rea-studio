"""Reusable xref-chasing helper.

Given a list of hits from search_strings / search_symbols / search_procedures,
resolve each to the containing function, decompile it, and return structured
results. Handles dedup and caching within a single run.

Usage:
    from xrefs_util import chase_hits
    results = await chase_hits(client, hits, source_label="string 'example'",
                                log=print)
"""
from __future__ import annotations

from typing import Any, Callable


def _unwrap(data: Any) -> Any:
    if isinstance(data, dict):
        for k in ("normalized_result", "result"):
            if k in data:
                return data[k]
    return data


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _hit_address(hit: Any) -> str:
    return str(_as_dict(hit).get("address") or "")


def _hit_value(hit: Any) -> str:
    return str(_as_dict(hit).get("value") or "")


async def chase_hits(client, hits: list, source_label: str,
                     log: Callable[[str], None] = print,
                     max_xrefs_per_hit: int = 8,
                     analyze: bool = True,
                     cache: dict | None = None) -> list[dict]:
    """For each hit: xrefs -> resolve_containing_procedure -> analyze_function.

    Returns a list of:
        {"source": str, "value": str, "hit_address": str,
         "caller_address": str | None, "function": dict, "pseudocode": str | None}

    Deduplicates functions by address so we don't re-analyze the same one.
    If `cache` is provided, it must be a dict; it accumulates `{addr: dossier}`
    across calls so a driver processing many sources only analyzes once.
    """
    if cache is None:
        cache = {}
    out: list[dict] = []

    for hit in hits:
        addr = _hit_address(hit)
        val = _hit_value(hit)
        if not addr:
            continue

        # 1. xrefs to the hit address
        try:
            xr_raw = _unwrap(await client.call_tool("xrefs", {"address": addr}))
        except Exception as e:
            log(f"    xrefs {addr} failed: {e}")
            continue
        xr = [x for x in _as_list(xr_raw) if isinstance(x, str)]

        # 2. If no xrefs, the hit might itself be inside a function (search_procedures).
        if not xr:
            proc = await _resolve(client, addr, log)
            if proc:
                dossier = await _analyze(client, proc["address"], cache, log) if analyze else None
                out.append({
                    "source": source_label, "value": val, "hit_address": addr,
                    "caller_address": None, "function": proc,
                    "pseudocode": _as_dict(dossier).get("pseudocode"),
                })
            continue

        # 3. Chase each xref site.
        for src in xr[:max_xrefs_per_hit]:
            proc = await _resolve(client, src, log)
            if not proc:
                continue
            dossier = await _analyze(client, proc["address"], cache, log) if analyze else None
            out.append({
                "source": source_label, "value": val, "hit_address": addr,
                "caller_address": src, "function": proc,
                "pseudocode": _as_dict(dossier).get("pseudocode"),
            })

    return out


async def _resolve(client, addr: str, log) -> dict | None:
    try:
        r = _unwrap(await client.call_tool("resolve_containing_procedure",
                                           {"address": addr}))
    except Exception as e:
        log(f"    resolve {addr} failed: {e}")
        return None
    r = _as_dict(r)
    if not r.get("found"):
        return None
    proc = _as_dict(r.get("procedure"))
    return proc if proc.get("address") else None


async def _analyze(client, proc_addr: str, cache: dict, log) -> dict | None:
    if proc_addr in cache:
        return cache[proc_addr]
    try:
        b = _unwrap(await client.call_tool("analyze_function",
                                           {"procedure": proc_addr}))
    except Exception as e:
        log(f"    analyze {proc_addr} failed: {e}")
        return None
    b = _as_dict(b)
    if b:
        cache[proc_addr] = b
    return b or None


async def analyze_procedures(client, hits: list, source_label: str,
                             log: Callable[[str], None] = print,
                             cache: dict | None = None) -> list[dict]:
    """For search_procedures results, the hit *is* the function."""
    if cache is None:
        cache = {}
    out: list[dict] = []
    for hit in hits:
        addr = _hit_address(hit)
        name = _hit_value(hit)
        if not addr:
            continue
        dossier = await _analyze(client, addr, cache, log)
        out.append({
            "source": source_label, "value": name, "hit_address": addr,
            "caller_address": None,
            "function": {"address": addr, "name": name},
            "pseudocode": _as_dict(dossier).get("pseudocode"),
        })
    return out