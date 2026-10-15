"""Finding dataclass.

Existing code (autotriage.py, findcrypt.py, packer_detect.py) emits dicts of
the form {"kind", "severity", "title", "detail", "address", "source", "step"}.
This module accepts those and emits the same shape, so both coexist.

New code should use Finding and convert with to_dict() when writing reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


SEVERITIES = ("high", "warn", "info", "low")
SEV_ORDER = {"high": 0, "warn": 1, "info": 2, "low": 3}


@dataclass
class Finding:
    kind: str
    severity: str = "info"
    title: str = ""
    detail: str = ""
    address: str | None = None
    source: str = "auto"
    confidence: str = "medium"    # low | medium | high
    evidence: dict = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    step: int = 0

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "info"
        if self.confidence not in ("low", "medium", "high"):
            self.confidence = "medium"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        # Tolerate existing dicts that lack the new fields.
        return cls(
            kind=str(d.get("kind", "unknown")),
            severity=str(d.get("severity", "info")),
            title=str(d.get("title", "")),
            detail=str(d.get("detail", "")),
            address=d.get("address"),
            source=str(d.get("source", "auto")),
            confidence=str(d.get("confidence", "medium")),
            evidence=dict(d.get("evidence") or {}),
            step=int(d.get("step", 0)),
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.kind, f.address or ""))


def summarize(findings: list[Finding]) -> dict:
    out = {s: 0 for s in SEVERITIES}
    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        by_source[f.source] = by_source.get(f.source, 0) + 1
    return {"severities": out, "by_kind": by_kind, "by_source": by_source,
            "total": len(findings)}