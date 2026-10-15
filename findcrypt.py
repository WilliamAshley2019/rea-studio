"""Crypto-constant scanner, driven by decode_d3v.py's manifest.

For each table in d3v_manifest.json we look for its leading bytes in the
target file (fast path), then confirm the full table (slow path). Results
are Findings so they flow into the same report as string categories.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "d3v_manifest.json"


@dataclass
class CryptoHit:
    table: str
    offset: int
    length: int
    matched_bytes: int
    short_sample: str


def _load_tables(manifest_path: Path) -> list[tuple[str, bytes]]:
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    out: list[tuple[str, bytes]] = []
    for entry in raw.get("entries", []):
        sample = entry.get("sample") or []
        if not sample:
            continue
        esz = int(entry.get("element_size") or 0)
        try:
            if esz == 4:
                blob = b"".join(int(w, 16).to_bytes(4, "little") for w in sample)
            elif esz == 8:
                blob = b"".join(int(w, 16).to_bytes(8, "little") for w in sample)
            elif esz == 1:
                blob = bytes(int(w, 16) & 0xFF for w in sample)
            else:
                continue
        except (ValueError, OverflowError):
            continue
        if len(blob) >= 8:
            out.append((entry["name"], blob))
    return out


def scan(path: str, manifest_path: Path = DEFAULT_MANIFEST,
         min_prefix: int = 8) -> list[CryptoHit]:
    tables = _load_tables(manifest_path)
    if not tables:
        return []
    data = Path(path).read_bytes()
    hits: list[CryptoHit] = []
    seen_offsets: set[tuple[int, str]] = set()
    for name, blob in tables:
        needle = blob[:min_prefix]
        start = 0
        while True:
            off = data.find(needle, start)
            if off < 0:
                break
            if len(blob) > len(needle):
                if data[off:off + len(blob)] != blob:
                    start = off + 1
                    continue
            key = (off, name)
            if key in seen_offsets:
                start = off + 1
                continue
            seen_offsets.add(key)
            hits.append(CryptoHit(
                table=name, offset=off, length=len(blob),
                matched_bytes=len(blob),
                short_sample=blob[:16].hex(),
            ))
            start = off + 1
    hits.sort(key=lambda h: (h.offset, h.table))
    return hits


def scan_and_record(path: str, manifest_path: Path = DEFAULT_MANIFEST) -> list[CryptoHit]:
    try:
        return scan(path, manifest_path)
    except FileNotFoundError:
        return []