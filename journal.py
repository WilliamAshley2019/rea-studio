"""Append-only journal of every tool call, so a human session can be replayed
or turned into a recipe later (sessions/journal-YYYYMMDD.jsonl)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import config


def record(tool: str, args: dict, data: Any, is_error: bool) -> None:
    try:
        d = config.APP_DIR / "sessions"
        d.mkdir(exist_ok=True)
        path = d / f"journal-{datetime.now():%Y%m%d}.jsonl"
        entry = {"ts": datetime.now().isoformat(timespec="seconds"), "tool": tool,
                 "args": args, "is_error": is_error, "result": data}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception:  # noqa: BLE001 - journaling must never break a call
        pass


def availability_note(data: Any) -> str | None:
    """If a result says the tool is unavailable, return a one-line reason."""
    if isinstance(data, dict) and data.get("available") is False:
        reason = data.get("reason") or data.get("code") or data.get("detail") or "no reason given"
        return f"Tool unavailable on this host: {reason}"
    return None
