"""Auto Analyze: pick files -> detect how to open them -> run a static triage
through REA -> write a report folder.

Static only. This module never calls tools that launch or instrument the
target (no *_frida_*, observe_*, capture_*_scenario, adb install/start...).

Result shapes used (taken from REA 6.4.0's published outputSchema):
  open_binary / binary_session      -> {"result": {...}}
  most other tools                  -> envelope with "normalized_result"
  list_procedures                   -> [{address, value, ...}]
  list_strings / search_strings     -> [{address, value, ...}]
  xrefs                             -> [address, ...]
  resolve_containing_procedure      -> {query_address, found, procedure|null}
  analyze_function                  -> {procedure{address,name,signature}, pseudocode,
                                        callers[], callees[], referenced_strings[], ...}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import journal
import detect as detect_mod
import findcrypt
import packer_detect
import entropy as entropy_mod
from exttools import load as load_ext

NATIVE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".drv", ".scr", ".cpl", ".efi", ".so", ".dylib", ".com"}
SCRIPT_EXTS = {".js", ".mjs", ".cjs", ".map", ".plist"}
ARCHIVE_EXTS = {".apk", ".jar", ".aar", ".zip", ".asar", ".ipa"}

PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "arm", 0x200: "ia64"}
ELF_MACHINES = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64", 8: "mips"}
MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}

ENTRY_RE = re.compile(
    r"^(entry|_?main|_?wmain|_?w?WinMain|_?DllMain|_?DllEntryPoint|start|_start|"
    r"(w?main|w?WinMain|DllMain)CRTStartup|TlsCallback_\d+)$", re.I)
AUTO_NAME_RE = re.compile(r"^(FUN_|sub_|thunk_FUN_|LAB_|DAT_)", re.I)

CATS: list[tuple[str, re.Pattern]] = [(label, re.compile(rx, re.I)) for label, rx in [
    ("Credential / license", r"passw(or)?d|passwd|secret|token|api[_ -]?key|licen[sc]e|serial|activation|unlock|\bkey\b"),
    ("URL", r"https?://[^\s\"']+|ftp://"),
    ("Registry", r"HKEY_|SOFTWARE\\|\\CurrentVersion\\"),
    ("Error / message", r"error|fail(ed|ure)?|exception|invalid|denied|cannot|unable|corrupt|not found"),
    ("File path", r"[A-Za-z]:\\|\\\\[A-Za-z0-9_.$-]+\\|%[A-Za-z_]+%|/etc/|/usr/|/tmp/"),
    ("DLL / EXE name", r"\b[\w.-]+\.(dll|exe|sys|ocx|drv)\b"),
    ("Debug / PDB", r"\.pdb\b|assert|debug|trace"),
    ("Network / IP / email", r"\b\d{1,3}(\.\d{1,3}){3}\b|[\w.+-]+@[\w-]+\.[\w.]+"),
    ("Version / copyright", r"copyright|\(c\)|version|\bv\d+\.\d+"),
]]
CAT_PRIORITY = [c for c, _ in CATS]


# ----------------------------------------------------------------- detection
@dataclass
class Detection:
    path: str
    size: int
    kind: str                       # pe | pe-managed | elf | macho | dos-com | script | archive | unknown
    label: str
    open_args: dict = field(default_factory=dict)
    native: bool = True
    managed: bool = False
    notes: list[str] = field(default_factory=list)


def _parse_pe(f, size: int) -> dict | None:
    f.seek(0)
    dos = f.read(64)
    if len(dos) < 64 or dos[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > size:
        return {"dos_only": True}
    f.seek(e_lfanew)
    if f.read(4) != b"PE\0\0":
        return {"dos_only": True}
    machine, _nsec, _ts, _ptr, _nsym, optsize, chars = struct.unpack("<HHIIIHH", f.read(20))
    opt = f.read(min(optsize, 240))
    magic = struct.unpack_from("<H", opt, 0)[0] if len(opt) >= 2 else 0
    dd_off = 96 if magic == 0x10B else 112 if magic == 0x20B else None
    managed = False
    if dd_off and len(opt) >= dd_off + 8 * 15:
        rva, sz = struct.unpack_from("<II", opt, dd_off + 8 * 14)   # CLR runtime header directory
        managed = bool(rva and sz)
    return {"machine": PE_MACHINES.get(machine, hex(machine)), "dll": bool(chars & 0x2000), "managed": managed}


def detect(path: str, raw_arch: str | None = None, raw_entry: str | None = None) -> Detection:
    p = os.path.abspath(path.strip().strip('"'))
    size = os.path.getsize(p)
    ext = os.path.splitext(p)[1].lower()
    with open(p, "rb") as f:
        head = f.read(64)
        pe = _parse_pe(f, size)
    if pe and not pe.get("dos_only"):
        what = "DLL" if pe["dll"] else "EXE"
        if pe["managed"]:
            return Detection(p, size, "pe-managed", f".NET {what} ({pe['machine']})", {}, native=False, managed=True,
                             notes=["Managed (.NET) assembly: native disassembly is not useful, so the managed inspectors run instead."])
        return Detection(p, size, "pe", f"Windows PE {what} ({pe['machine']})")
    if pe and pe.get("dos_only"):
        return Detection(p, size, "dos-mz", "DOS MZ executable (no PE header)",
                         notes=["Opened with REA's header-based detection (DOS MZ)."])
    if head[:4] == b"\x7fELF":
        little = head[5] != 2
        mach = struct.unpack_from("<H" if little else ">H", head, 18)[0]
        return Detection(p, size, "elf", f"ELF {32 if head[4] == 1 else 64}-bit ({ELF_MACHINES.get(mach, mach)})")
    if head[:4] in MACHO_MAGICS:
        return Detection(p, size, "macho", "Mach-O")
    if ext == ".com" and 1 <= size <= 65280:
        return Detection(p, size, "dos-com", "DOS COM (headerless)", {"format": "dos-com"})
    if head[:4] == b"PK\x03\x04" or ext in ARCHIVE_EXTS:
        return Detection(p, size, "archive", "Archive / package", native=False,
                         notes=["Opened as an archive; inspect_artifact summarizes its contents."])
    if ext in SCRIPT_EXTS:
        return Detection(p, size, "script", f"Script/data ({ext})", native=False,
                         notes=["Opened for inspection. For JavaScript apps use analyze_javascript_application in the Tools tab."])
    if raw_arch and raw_entry:
        return Detection(p, size, "raw", f"Raw binary as {raw_arch} @ {raw_entry}",
                         {"format": "raw-binary", "architecture": raw_arch, "entry_point": raw_entry})
    return Detection(p, size, "unknown", "Unrecognized format",
                     notes=["REA will try its own detection. If it refuses, this is probably a headerless dump: "
                            "supply the CPU (x86, x86_64, arm, arm64, 6502) and the load/entry address."])


def expand_paths(paths: list[str], recursive: bool = False) -> list[str]:
    out: list[str] = []
    for raw in paths:
        p = os.path.abspath(raw.strip().strip('"'))
        if os.path.isdir(p):
            it = Path(p).rglob("*") if recursive else Path(p).glob("*")
            out += sorted(str(x) for x in it if x.is_file() and x.suffix.lower() in NATIVE_EXTS)
        else:
            out.append(p)
    seen, uniq = set(), []
    for p in out:
        if p.lower() not in seen:
            seen.add(p.lower())
            uniq.append(p)
    return uniq


# ------------------------------------------------------------------- helpers
def body(data: Any) -> Any:
    """Unwrap REA's two result envelopes."""
    if isinstance(data, dict):
        for k in ("normalized_result", "result"):
            if k in data:
                return data[k]
    return data


def _s(v: Any, n: int = 100) -> str:
    t = str(v).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return t if len(t) <= n else t[: n - 1] + "…"


def _list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60] or "file"


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def categorize(strings: list[tuple[str, str]], patterns: list[str]):
    cats: dict[str, list] = {label: [] for label in CAT_PRIORITY}
    custom: dict[str, list] = {p: [] for p in patterns}
    for addr, val in strings:
        if len(val) < 4:
            continue
        for label, rx in CATS:
            if rx.search(val):
                cats[label].append((addr, val))
        low = val.lower()
        for p in patterns:
            if p.lower() in low:
                custom[p].append((addr, val))
    return cats, custom


# -------------------------------------------------------------------- runner
@dataclass
class Options:
    out_root: Path
    top_functions: int = 6
    string_links: int = 8
    quick: bool = False
    export_evidence: bool = True
    patterns: list[str] = field(default_factory=list)
    raw_arch: str | None = None
    raw_entry: str | None = None
    pseudocode_lines: int = 60
    cancel: threading.Event = field(default_factory=threading.Event)


class Cancelled(Exception):
    pass


class StepFailed(Exception):
    pass


class Runner:
    def __init__(self, client, det: Detection, opts: Options, out_dir: Path, log: Callable[[str], None]):
        self.client, self.det, self.opts, self.out_dir, self.log = client, det, opts, out_dir, log
        self.raw_dir = out_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.steps: list[dict] = []
        self.facts: dict[str, Any] = {}
        self.findings: list[dict] = []
        self.n = 0

    def add_finding(self, kind: str, severity: str, title: str,
                    detail: str = "", address: str | None = None,
                    source: str = "auto") -> None:
        self.findings.append({
            "kind": kind, "severity": severity, "title": title,
            "detail": detail, "address": address, "source": source,
            "step": self.n,
        })

    def _absorb_external(self, name: str, data: dict) -> None:
        if name == "capa":
            from exttools.capa_tool import normalize
            for r in normalize(data):
                self.add_finding("capability", "info", title=r["rule"],
                                 detail=f"namespace={r['namespace']} scope={r['scope']} attack={r['attack']}",
                                 source="capa")
        elif name == "floss":
            from exttools.floss_tool import normalize
            for bucket, items in normalize(data).items():
                for s in items[:200]:
                    self.add_finding("string", "info",
                                     title=f"FLOSS {bucket}: {s[:80]}",
                                     detail=f"source=floss bucket={bucket}",
                                     source="floss")
        elif name == "yara":
            for m in (data.get("matches") or []):
                self.add_finding("yara", "warn" if m.get("tags") else "info",
                                 title=f"YARA: {m['rule']}",
                                 detail=f"tags={m.get('tags')} meta={m.get('meta')}",
                                 source="yara")
        elif name == "pdb":
            if data.get("available"):
                self.add_finding("symbols", "info",
                                 title=f"PDB available: {data.get('sym_name')}",
                                 detail=f"GUID={data.get('guid')} age={data.get('age')}",
                                 source="pdb")
            elif data.get("sym_name"):
                self.add_finding("symbols", "warn",
                                 title=f"PDB known but not downloaded: {data.get('sym_name')}",
                                 detail=f"reason={data.get('reason')}",
                                 source="pdb")
        elif name == "pefile":
            imp_count = sum(len(v) for v in (data.get("imports") or {}).values())
            if imp_count < 10:
                self.add_finding("imports", "warn",
                                 title=f"Only {imp_count} imports",
                                 detail=f"subsystem={data.get('subsystem')}",
                                 source="pefile")

    async def call(self, label: str, tool: str, args: dict, required: bool = False) -> Any:
        if self.opts.cancel.is_set():
            raise Cancelled()
        self.n += 1
        rec = {"n": self.n, "step": label, "tool": tool, "status": "ok", "note": "", "seconds": 0.0}
        self.log(f"  [{self.n}] {label}  ({tool})")
        t0 = time.time()
        raw: Any = None
        data: Any = None
        try:
            res = await self.client.call_tool(tool, args)
            raw = res.data
            journal.record(tool, args, raw, res.is_error)
            note = journal.availability_note(raw)
            if note:
                rec.update(status="unavailable", note=note)
            elif res.is_error:
                rec.update(status="error", note=_s(raw, 300))
            else:
                data = raw
        except Exception as e:  # noqa: BLE001
            rec.update(status="error", note=_s(e, 300))
            raw = {"exception": str(e)}
        rec["seconds"] = round(time.time() - t0, 1)
        if isinstance(data, dict) and "provider" in data and "provider" not in self.facts:
            prov = _dict(data["provider"])
            self.facts["provider"] = f"{prov.get('name', '?')} {prov.get('version') or ''}".strip()
        try:
            (self.raw_dir / f"{self.n:02d}_{tool}.json").write_text(
                json.dumps({"tool": tool, "args": args, "result": raw}, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        except OSError:
            pass
        self.steps.append(rec)
        self.log(f"      {rec['status']} in {rec['seconds']}s" + (f" - {rec['note']}" if rec["note"] else ""))
        if required and data is None:
            raise StepFailed(f"{tool} failed: {rec['note'] or rec['status']}")
        return data

    # ---- pipelines -----------------------------------------------------
    async def run(self) -> str:
        det, status = self.det, "complete"
        try:
            if det.managed:
                await self._managed()
            elif det.kind == "archive":
                await self._open()
                await self.call("Inspect archive", "inspect_artifact", {"detail": "summary"})
            elif det.kind == "script":
                await self._open()
            else:
                await self._native()
            if self.opts.export_evidence:
                await self.call("Export evidence bundle", "export_evidence_bundle",
                                {"path": str(self.out_dir / "evidence.json"), "overwrite": False})
        except Cancelled:
            status = "cancelled"
        except StepFailed as e:
            status = "failed"
            self.facts["failure"] = str(e)
            self.log(f"  FAILED: {e}")
        return status

    async def _open(self) -> dict:
        args = {"path": self.det.path, **self.det.open_args}
        opened = await self.call("Open in REA (first analysis can take 30-90 s)", "open_binary", args, required=True)
        self.facts["opened"] = _dict(body(opened))
        await self.call("Session status", "binary_session", {})
        return self.facts["opened"]

    async def _managed(self) -> None:
        p = self.det.path
        self.facts["managed"] = body(await self.call("Managed assembly summary", "inspect_managed_artifact",
                                                     {"path": p, "detail": "summary"}))
        await self.call("Managed members", "inspect_managed_members", {"path": p})

    async def _native(self) -> None:
        det = self.det

        # --- local detectors (fast, no MCP needed) -----------------------
        try:
            hits = findcrypt.scan_and_record(det.path)
        except Exception as e:
            hits = []
            self.add_finding("crypto-constant", "warn",
                             title="findcrypt failed", detail=str(e), source="findcrypt")
        for h in hits:
            self.add_finding(
                kind="crypto-constant", severity="info",
                title=f"Crypto table matched: {h.table}",
                detail=f"offset 0x{h.offset:X}, {h.length} bytes, first bytes {h.short_sample}",
                address=f"0x{h.offset:X}", source="findcrypt")
        if hits:
            self.log(f"  findcrypt: {len(hits)} table match(es)")

        try:
            pv = packer_detect.detect(det.path)
        except Exception as e:
            pv = None
            self.add_finding("packer", "warn",
                             title="packer_detect failed", detail=str(e), source="packer_detect")
        if pv is not None:
            if pv.packed:
                self.add_finding("packer", "warn",
                                 title=f"Packer detected: {pv.family or 'unknown'} ({pv.confidence})",
                                 detail="; ".join(pv.signals), source="packer_detect")
                self.log(f"  packer_detect: {pv.summary()}")
            if pv.die_output is not None:
                self.facts.setdefault("_ext", {})["diec"] = pv.die_output

        try:
            ep = entropy_mod.profile(det.path)
        except Exception:
            ep = None
        if ep is not None:
            if ep.high_windows:
                self.add_finding("entropy", "info",
                                 title=f"High entropy in {ep.high_windows} window(s)",
                                 detail=f"overall {ep.overall:.2f}, max {ep.max_window:.2f} at 0x{ep.max_window_offset:X}",
                                 source="entropy")
            self.facts["entropy"] = {
                "overall": round(ep.overall, 3),
                "high_windows": ep.high_windows,
                "sparkline": entropy_mod.sparkline(ep),
                "verdict": ep.verdict(),
            }

        # --- external wrappers (best-effort, skip if missing) ------------
        for name in ("pdb", "capa", "floss", "yara", "pefile"):
            try:
                mod = load_ext(name)
                if not mod.available():
                    continue
                data = mod.run(det.path)
            except Exception as e:
                self.add_finding("external", "warn",
                                 title=f"{name}: failed", detail=str(e), source=name)
                continue
            if data is None:
                continue
            self.facts.setdefault("_ext", {})[name] = data
            try:
                self._absorb_external(name, data)
            except Exception:
                pass
            self.log(f"  {name}: ok")

        # --- now the REA pipeline ----------------------------------------
        await self._open()
        ov = _dict(body(await self.call("Overview", "binary_overview", {})))
        self.facts["overview"] = ov
        self.facts["segments"] = _list(body(await self.call("Segments", "list_segments", {})))
        procs = _list(body(await self.call("List procedures", "list_procedures", {})))
        self.facts["procedures"] = [(str(_dict(x).get("address", "")), str(_dict(x).get("value", ""))) for x in procs]
        strs = _list(body(await self.call("List strings", "list_strings", {})))
        self.facts["strings"] = [(str(_dict(x).get("address", "")), str(_dict(x).get("value", ""))) for x in strs]
        if not self.facts["strings"] and self.opts.patterns:      # list_strings failed: fall back to searching
            for pat in self.opts.patterns:
                hits = _list(body(await self.call(f"Search strings for '{pat}'", "search_strings",
                                                  {"pattern": pat, "mode": "literal", "case_sensitive": False})))
                self.facts["strings"] += [(str(_dict(x).get("address", "")), str(_dict(x).get("value", ""))) for x in hits]
        if self.det.kind in ("pe", "dos-mz"):
            await self.call("File layout (static)", "inspect_binary_layout", {"path": self.det.path, "detail": "summary"})
            await self.call("PE resources (static)", "inspect_pe_resources", {"path": self.det.path})
        self.facts["cats"], self.facts["custom"] = categorize(self.facts["strings"], self.opts.patterns)
        if not self.opts.quick:
            await self._functions()

    def _pick_string_hits(self) -> list[tuple[str, str, str]]:
        cats, custom = self.facts["cats"], self.facts["custom"]
        order = [(f"custom '{p}'", custom[p]) for p in self.opts.patterns] + [(c, cats[c]) for c in CAT_PRIORITY]
        picked, seen = [], set()
        for label, items in order:
            took = 0
            for addr, val in items:
                if len(val) < 6 or val in seen or not addr:
                    continue
                seen.add(val)
                picked.append((label, addr, val))
                took += 1
                if took >= 2:
                    break
            if len(picked) >= self.opts.string_links:
                break
        return picked[: self.opts.string_links]

    async def _functions(self) -> None:
        cands: dict[str, str] = {}
        for addr, name in self.facts["procedures"]:
            if addr and ENTRY_RE.match(name) and len([r for r in cands.values() if r.startswith("entry")]) < 3:
                cands.setdefault(addr, f"entry/main-like name '{name}'")
        for label, saddr, val in self._pick_string_hits():
            if len(cands) >= self.opts.top_functions * 2:
                break
            xr = [x for x in _list(body(await self.call(f"Who references {label} string '{_s(val, 30)}'?",
                                                         "xrefs", {"address": saddr}))) if isinstance(x, str)][:2]
            for src in xr:
                r = _dict(body(await self.call(f"Function containing {src}", "resolve_containing_procedure",
                                               {"address": src})))
                proc = _dict(r.get("procedure"))
                if r.get("found") and proc.get("address"):
                    cands.setdefault(str(proc["address"]), f"references {label} string \"{_s(val, 40)}\"")
        analyzed = []
        for addr, why in list(cands.items())[: self.opts.top_functions]:
            b = _dict(body(await self.call(f"Analyze function {addr}", "analyze_function", {"procedure": addr})))
            if b:
                analyzed.append({"address": addr, "why": why, "data": b})
        self.facts["analyzed"] = analyzed


# -------------------------------------------------------------------- report
def _perm(seg: dict) -> str:
    return "".join(c if seg.get(k) else "-" for c, k in (("R", "readable"), ("W", "writable"), ("X", "executable")))


def write_outputs(runner: Runner, status: str, seconds: float) -> Path:
    det, facts, out = runner.det, runner.facts, runner.out_dir
    opened = _dict(facts.get("opened"))
    ov = _dict(facts.get("overview"))
    segs = [_dict(s) for s in _list(facts.get("segments"))]
    procs = facts.get("procedures", [])
    strs = facts.get("strings", [])
    try:
        local_sha = sha256_of(det.path)
    except OSError:
        local_sha = "?"

    if procs:
        (out / "procedures.tsv").write_text("address\tname\n" + "\n".join(f"{a}\t{_s(n, 200)}" for a, n in procs), encoding="utf-8")
    if strs:
        (out / "strings.tsv").write_text("address\tstring\n" + "\n".join(f"{a}\t{_s(v, 400)}" for a, v in strs), encoding="utf-8")

    L: list[str] = []
    L.append(f"# Analysis report: {os.path.basename(det.path)}\n")
    L.append(f"- **Status:** {status} ({seconds:.0f} s, {datetime.now():%Y-%m-%d %H:%M})")
    L.append(f"- **File:** `{det.path}` ({det.size:,} bytes)")
    L.append(f"- **SHA-256:** `{local_sha}`")
    if opened.get("sha256") and opened["sha256"] != local_sha:
        L.append(f"- **WARNING:** REA reports a different SHA-256 (`{opened['sha256']}`); the file may have changed during analysis.")
    L.append(f"- **Detected:** {det.label}" + (f" | REA format: {opened.get('format')}, arch: {opened.get('architecture')}" if opened else ""))
    if facts.get("provider"):
        L.append(f"- **Analysis provider:** {facts['provider']}")
    for n in det.notes:
        L.append(f"- Note: {n}")
    if facts.get("failure"):
        L.append(f"- **Failure:** {facts['failure']}")
    L.append("- Mode: static analysis only. The file was never executed.\n")

    if ov or procs or strs:
        auto = sum(1 for _, n in procs if AUTO_NAME_RE.match(n))
        L.append("## Summary\n")
        L.append("| Item | Count |\n|---|---|")
        L.append(f"| Segments | {ov.get('segment_count', len(segs))} |")
        L.append(f"| Procedures | {ov.get('procedure_count', len(procs))} ({len(procs) - auto} named, {auto} auto-named) |")
        L.append(f"| Strings | {ov.get('string_count', len(strs))} |")
        if ov.get("image_base"):
            L.append(f"| Image base | `{ov['image_base']}` |")
        L.append("")

    findings = getattr(runner, "findings", [])
    if findings:
        L.append("## Findings\n")
        L.append("| Severity | Kind | Title | Source | Address |")
        L.append("|---|---|---|---|---|")
        sev_order = {"high": 0, "warn": 1, "info": 2, "low": 3}
        for f in sorted(findings, key=lambda x: (sev_order.get(x["severity"], 9), x["kind"])):
            L.append(f"| {f['severity']} | {f['kind']} | {_s(f['title'], 90)} | {f['source']} | "
                     f"{f['address'] or ''} |")
        L.append("")
        if runner.facts.get("entropy", {}).get("sparkline"):
            L.append("### Entropy profile\n")
            L.append("```")
            L.append(runner.facts["entropy"]["sparkline"])
            L.append("```")
            L.append(f"_{runner.facts['entropy']['verdict']}_\n")

    if segs:
        L.append("## Segments\n")
        L.append("| Name | Start | End | Perms |\n|---|---|---|---|")
        for s in segs:
            L.append(f"| {s.get('name', '?')} | `{s.get('start', '?')}` | `{s.get('end', '?')}` | {_perm(s)} |")
        wx = [s.get("name") for s in segs if s.get("writable") and s.get("executable")]
        if wx:
            L.append(f"\n> Writable **and** executable segment(s): {', '.join(map(str, wx))}. Common in packed or self-modifying code.")
        L.append("")

    entries = [(a, n) for a, n in procs if ENTRY_RE.match(n)]
    if entries:
        L.append("## Entry-point-like functions\n")
        L += [f"- `{a}` {n}" for a, n in entries[:20]]
        L.append("")

    cats = facts.get("cats") or {}
    custom = facts.get("custom") or {}
    if cats or custom:
        L.append("## Interesting strings\n")
        groups = [(f"Custom: {p}", v) for p, v in custom.items()] + [(c, cats.get(c, [])) for c in CAT_PRIORITY]
        for label, items in groups:
            if not items:
                continue
            L.append(f"**{label}** ({len(items)})")
            L += [f"- `{a}` {_s(v)}" for a, v in items[:10]]
            if len(items) > 10:
                L.append(f"- … {len(items) - 10} more in strings.tsv")
            L.append("")

    analyzed = facts.get("analyzed") or []
    if analyzed:
        L.append("## Functions analyzed\n")
        for item in analyzed:
            b = item["data"]
            proc = _dict(b.get("procedure"))
            name, sig = proc.get("name", "?"), proc.get("signature")
            callers = [_dict(c).get("name", "?") for c in _list(b.get("callers"))]
            callees = [_dict(c).get("name", "?") for c in _list(b.get("callees"))]
            rstr = [_dict(c).get("value", "") for c in _list(b.get("referenced_strings"))]
            L.append(f"### `{item['address']}` {name}\n")
            L.append(f"*Selected because:* {item['why']}\n")
            if sig:
                L.append(f"- Signature: `{_s(sig, 200)}`")
            L.append(f"- Callers ({len(callers)}): {', '.join(map(str, callers[:8])) or 'none found'}")
            L.append(f"- Callees ({len(callees)}): {', '.join(map(str, callees[:12])) or 'none found'}")
            if rstr:
                L.append(f"- Strings used: " + "; ".join(f"`{_s(x, 50)}`" for x in rstr[:6]))
            pseudo = str(b.get("pseudocode") or "").splitlines()
            if pseudo:
                cut = pseudo[: runner.opts.pseudocode_lines]
                L.append("\n```c\n" + "\n".join(cut) + ("\n/* … truncated … */" if len(pseudo) > len(cut) else "") + "\n```")
            L.append("")

    managed = facts.get("managed")
    if managed:
        L.append("## Managed (.NET) summary\n")
        L.append("Full inventory is in `raw/`. Open it in the app's Evidence tab.\n")

    L.append("## Steps\n")
    L.append("| # | Step | Tool | Result | Seconds | Note |\n|---|---|---|---|---|---|")
    for r in runner.steps:
        L.append(f"| {r['n']} | {r['step']} | `{r['tool']}` | {r['status']} | {r['seconds']} | {_s(r['note'], 120)} |")
    L.append("")
    L.append("## Files in this folder\n")
    L.append("- `raw/` the full JSON REA returned for every step (open in the Evidence tab)")
    if (out / "evidence.json").exists():
        L.append("- `evidence.json` REA evidence bundle (reload with import_evidence_bundle)")
    if procs:
        L.append("- `procedures.tsv`, `strings.tsv` complete lists (open in Excel)")
    (out / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    summary = {
        "file": det.path, "status": status, "seconds": round(seconds, 1), "detected": det.label,
        "findings": getattr(runner, "findings", []),
        "procedures": len(procs), "strings": len(strs), "functions_analyzed": len(analyzed),
        "steps": runner.steps, "report": str(out / "report.md"),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return out / "report.md"


# --------------------------------------------------------------------- batch
async def analyze_files(client, paths: list[str], opts: Options, log: Callable[[str], None] = print) -> list[dict]:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    opts.out_root.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    for i, path in enumerate(paths, 1):
        if opts.cancel.is_set():
            break
        log(f"\n=== [{i}/{len(paths)}] {path}")
        try:
            det = detect(path, opts.raw_arch, opts.raw_entry)
        except OSError as e:
            log(f"  Cannot read file: {e}")
            results.append({"file": path, "status": "unreadable", "detected": "-", "report": "", "note": str(e)})
            continue
        log(f"  Detected: {det.label}")
        for n in det.notes:
            log(f"  Note: {n}")
        out_dir = opts.out_root / f"{_safe_name(Path(det.path).stem)}-{stamp}"
        k = 2
        while out_dir.exists():
            out_dir = opts.out_root / f"{_safe_name(Path(det.path).stem)}-{stamp}-{k}"
            k += 1
        runner = Runner(client, det, opts, out_dir, log)
        t0 = time.time()
        status = await runner.run()
        report = write_outputs(runner, status, time.time() - t0)
        log(f"  {status.upper()} - report: {report}")
        results.append({"file": path, "status": status, "detected": det.label, "report": str(report),
                        "procedures": len(runner.facts.get("procedures", [])),
                        "strings": len(runner.facts.get("strings", [])),
                        "analyzed": len(runner.facts.get("analyzed", []))})
        if status == "cancelled":
            break
    if len(results) > 1:
        rows = ["# Batch summary\n", "| File | Detected | Status | Procedures | Strings | Functions analyzed | Report |", "|---|---|---|---|---|---|---|"]
        for r in results:
            rows.append(f"| {os.path.basename(r['file'])} | {r['detected']} | {r['status']} | {r.get('procedures', '-')} | "
                        f"{r.get('strings', '-')} | {r.get('analyzed', '-')} | {r['report']} |")
        (opts.out_root / f"index-{stamp}.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
        log(f"\nBatch summary: {opts.out_root / f'index-{stamp}.md'}")
    return results