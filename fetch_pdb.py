"""Download a PE's matching PDB from a symbol server.

Searches Microsoft's public symbol server by default. Extracts the RSDS
GUID + Age from the PE's Debug Directory (IMAGE_DEBUG_TYPE_CODEVIEW).
Builds the canonical symbol path <symname>/<GUID><AGE>/<symname> and
downloads via plain HTTP.

Standard library only. No external tools.
"""
from __future__ import annotations

import argparse
import struct
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SERVER = "https://msdl.microsoft.com/download/symbols"
DEFAULT_CACHE = Path.home() / "Symbols"
USER_AGENT = "rea-studio/fetch_pdb"


@dataclass
class PdbInfo:
    path: str
    sym_name: str
    guid: str
    age: int
    symbol_url: str | None
    cached: str | None


def _hex_le(b: bytes) -> str:
    if len(b) != 16:
        return ""
    d1 = b[0:4]
    d2 = b[4:6]
    d3 = b[6:8]
    d4 = b[8:10]
    d5 = b[10:16]
    return (d1[::-1].hex() + d2[::-1].hex() + d3[::-1].hex()
            + d4.hex() + d5.hex()).upper()


def _find_debug_dir(data: bytes) -> dict | None:
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsize = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        dd_off = opt + 96
    elif magic == 0x20B:
        dd_off = opt + 112
    else:
        return None
    debug_rva = struct.unpack_from("<I", data, dd_off + 6*8)[0]
    debug_sz = struct.unpack_from("<I", data, dd_off + 6*8 + 4)[0]
    if debug_rva == 0 or debug_sz == 0:
        return None
    sec_off = opt + optsize
    file_off = None
    for i in range(nsec):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        va = struct.unpack_from("<I", data, base + 12)[0]
        vsz = struct.unpack_from("<I", data, base + 8)[0]
        rawsz = struct.unpack_from("<I", data, base + 16)[0]
        rawptr = struct.unpack_from("<I", data, base + 20)[0]
        if va <= debug_rva < va + max(vsz, rawsz):
            file_off = rawptr + (debug_rva - va)
            break
    if file_off is None:
        return None
    return {"file_off": file_off, "size": debug_sz, "n": debug_sz // 28}


def extract_pdb_info(pe_path: str) -> PdbInfo | None:
    data = Path(pe_path).read_bytes()
    dd = _find_debug_dir(data)
    if not dd:
        return None
    for i in range(dd["n"]):
        rec = dd["file_off"] + i * 28
        if rec + 28 > len(data):
            break
        _chars, _ts, _maj, _min, typ, szdata, addr, ptr = struct.unpack_from(
            "<IIHHIIII", data, rec)
        if typ != 2:
            continue
        if ptr + szdata > len(data):
            continue
        cv = data[ptr:ptr+szdata]
        if cv[:4] != b"RSDS":
            continue
        guid = _hex_le(cv[4:20])
        age = struct.unpack_from("<I", cv, 20)[0]
        name_end = cv.find(b"\x00", 24)
        if name_end < 0:
            name_end = len(cv)
        sym_name = cv[24:name_end].decode("ascii", errors="replace")
        if not sym_name:
            continue
        return PdbInfo(path=pe_path, sym_name=sym_name, guid=guid,
                       age=age, symbol_url=None, cached=None)
    return None


def _sym_path(sym_name: str, guid: str, age: int) -> str:
    return f"{sym_name}/{guid}{age:X}/{sym_name}"


def _try_download(url: str, dest: Path, timeout: int = 30) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            with open(tmp, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        tmp.replace(dest)
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError):
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def fetch(pe_path: str,
          cache_dir: str | Path = DEFAULT_CACHE,
          server: str = DEFAULT_SERVER,
          timeout: int = 30,
          verbose: bool = False) -> PdbInfo | None:
    info = extract_pdb_info(pe_path)
    if info is None:
        return None
    cache = Path(cache_dir)
    rel = _sym_path(info.sym_name, info.guid, info.age)
    local = cache / rel
    if local.is_file() and local.stat().st_size > 0:
        info.cached = str(local)
        if verbose:
            print(f"  cached: {local}")
        return info
    url = f"{server.rstrip('/')}/{rel}"
    info.symbol_url = url
    if verbose:
        print(f"  GET {url}")
    ok = _try_download(url, local, timeout=timeout)
    if ok:
        info.cached = str(local)
    return info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pe", help="Path to a PE (.exe/.dll/.sys)")
    ap.add_argument("--cache", default=str(DEFAULT_CACHE))
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    info = fetch(a.pe, cache_dir=a.cache, server=a.server,
                 timeout=a.timeout, verbose=a.verbose)
    if info is None:
        if a.json:
            import json
            print(json.dumps({"ok": False, "reason": "no RSDS debug record"}))
        else:
            print("No CodeView RSDS debug record found (nothing to fetch).")
        return 1
    if a.json:
        import json
        print(json.dumps({
            "ok": bool(info.cached),
            "path": info.path,
            "sym_name": info.sym_name,
            "guid": info.guid,
            "age": info.age,
            "symbol_url": info.symbol_url,
            "cached": info.cached,
        }))
    else:
        print(f"PDB name: {info.sym_name}")
        print(f"GUID:     {info.guid}")
        print(f"Age:      {info.age}")
        if info.cached:
            print(f"Cached:   {info.cached}")
        else:
            print(f"URL:      {info.symbol_url}")
            print("Download failed. Check network/TLS.")
    return 0 if info.cached else 2


if __name__ == "__main__":
    sys.exit(main())