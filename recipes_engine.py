"""Recipe engine: load YAML recipes and run them against a ReaClient.

Recipe format
-------------
name: Human name
description: What it does
inputs:
  - {name: binary_path, label: Binary, path: true, default: ""}
steps:
  - tool: open_binary
    args: {path: "{input.binary_path}"}
    save_as: opened            # optional; later steps use {result.opened.some.key}
    on_error: continue         # optional; default is to stop the recipe

A string that is exactly one placeholder keeps its real type (so a number
from an earlier result stays a number). Placeholders inside longer strings
are substituted as text.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import yaml

PLACEHOLDER = re.compile(r"\{(input|result)\.([^{}]+)\}")


def load_recipes(directory: Path) -> tuple[dict[str, dict], list[str]]:
    recipes: dict[str, dict] = {}
    problems: list[str] = []
    if directory.exists():
        for p in sorted(directory.glob("*.y*ml")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or "steps" not in data:
                    raise ValueError("missing 'steps'")
                recipes[p.stem] = data
            except Exception as e:  # noqa: BLE001
                problems.append(f"{p.name}: {e}")
    return recipes, problems


def _walk(path: str, root: Any) -> Any:
    cur = root
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur[part]
        elif isinstance(cur, list):
            cur = cur[int(part)]
        else:
            raise KeyError(path)
    return cur


def _lookup(kind: str, path: str, ctx: dict) -> Any:
    return _walk(path, ctx[kind])


def substitute(value: Any, ctx: dict) -> Any:
    if isinstance(value, str):
        m = PLACEHOLDER.fullmatch(value)
        if m:
            return _lookup(m.group(1), m.group(2), ctx)
        return PLACEHOLDER.sub(lambda m: str(_lookup(m.group(1), m.group(2), ctx)), value)
    if isinstance(value, dict):
        return {k: substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, ctx) for v in value]
    return value


async def run_recipe(client, recipe: dict, inputs: dict[str, str],
                     log: Callable[[str], None] = print, max_chars: int = 4000) -> dict:
    """Run all steps. Returns {"ok": bool, "results": {...}}."""
    ctx: dict = {"input": dict(inputs), "result": {}}
    ok = True
    steps = recipe.get("steps", [])
    for i, step in enumerate(steps, 1):
        tool = step["tool"]
        try:
            args = substitute(step.get("args", {}) or {}, ctx)
        except (KeyError, IndexError, ValueError) as e:
            log(f"[{i}/{len(steps)}] {tool}: cannot resolve placeholder {e}")
            ok = False
            break
        log(f"\n[{i}/{len(steps)}] >>> {tool}\n{json.dumps(args, indent=2, ensure_ascii=False)}")
        try:
            res = await client.call_tool(tool, args)
        except Exception as e:  # noqa: BLE001
            log(f"ERROR: {e}")
            if step.get("on_error") == "continue":
                continue
            ok = False
            break
        text = res.pretty()
        if len(text) > max_chars:
            text = text[:max_chars] + f"\n... ({len(text) - max_chars} more characters)"
        log(("<<< ERROR result\n" if res.is_error else "<<< result\n") + text)
        if "save_as" in step:
            ctx["result"][step["save_as"]] = res.data
        if res.is_error and step.get("on_error") != "continue":
            ok = False
            break
    log("\nRecipe finished." if ok else "\nRecipe stopped early.")
    return {"ok": ok, "results": ctx["result"]}
