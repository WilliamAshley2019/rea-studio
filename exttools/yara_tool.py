"""YARA: pip install yara-python

Looks for rule files in:
  <app>/yara_rules/                (user rules; .yar or .yara)
  ~/.yara/rules/                   (personal)
  REA_YARA_RULES env var (path-separator separated dirs or files)

If no rules are found, available() is False.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import yara
except ImportError:
    yara = None

APP_RULES = Path(__file__).resolve().parent.parent / "yara_rules"


def _rule_files() -> list[Path]:
    files: list[Path] = []
    for d in [APP_RULES, Path.home() / ".yara" / "rules"]:
        if d.is_dir():
            files += [p for p in d.rglob("*") if p.suffix.lower() in (".yar", ".yara")]
    env = os.environ.get("REA_YARA_RULES")
    if env:
        for part in env.replace(";", os.pathsep).split(os.pathsep):
            p = Path(part)
            if p.is_file():
                files.append(p)
            elif p.is_dir():
                files += [q for q in p.rglob("*") if q.suffix.lower() in (".yar", ".yara")]
    return files


def available() -> bool:
    return yara is not None and bool(_rule_files())


def run(path: str) -> dict | None:
    if yara is None:
        return None
    files = _rule_files()
    if not files:
        return None
    ns_map = {f"ns{i}": str(f) for i, f in enumerate(files)}
    rules = None
    try:
        rules = yara.compile(filepaths=ns_map)
    except Exception:
        # One bad rule kills the whole compile; try file-by-file.
        good = {}
        for ns, f in ns_map.items():
            try:
                yara.compile(filepaths={ns: f})
                good[ns] = f
            except Exception:
                continue
        if good:
            try:
                rules = yara.compile(filepaths=good)
            except Exception:
                rules = None
        if rules is None:
            return None
    try:
        matches = rules.match(path)
    except Exception:
        return None
    out = []
    for m in matches:
        out.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": [
                {"identifier": s.identifier,
                 "offset": s.instances[0].offset if s.instances else None}
                for s in m.strings
            ][:20],
        })
    return {"matches": out}