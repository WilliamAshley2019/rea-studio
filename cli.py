"""Headless command line for REA Studio.

  python main.py cli list [FILTER]          (! marks destructive tools)
  python main.py cli describe TOOL
  python main.py cli call TOOL ['{"json":"args"}'] [--yes]
  python main.py cli recipes
  python main.py cli recipe NAME -i key=value -i key2=value2
  python main.py cli detect FILE [FILE...]  (what REA Studio would do with a file; no REA needed)
  python main.py cli auto FILE_OR_FOLDER [...] [--out DIR] [--top N] [--quick] [-r]
                          [--pattern TEXT]... [--arch CPU --entry 0xADDR] [--no-evidence]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import config
import journal
from mcp_client import ReaClient
from recipes_engine import load_recipes, run_recipe

RECIPES_DIR = config.APP_DIR / "recipes"


async def _with_client(fn):
    cfg = config.load()
    async with ReaClient.from_config(cfg) as client:
        return await fn(client)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="rea-studio cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list"); s.add_argument("filter", nargs="?", default="")
    s = sub.add_parser("describe"); s.add_argument("tool")
    s = sub.add_parser("call"); s.add_argument("tool"); s.add_argument("args", nargs="?", default="{}")
    s.add_argument("--yes", action="store_true", help="allow tools REA marks destructive")
    sub.add_parser("recipes")
    s = sub.add_parser("recipe"); s.add_argument("name")
    s.add_argument("-i", "--input", action="append", default=[], metavar="KEY=VALUE")
    s = sub.add_parser("detect"); s.add_argument("files", nargs="+")
    s = sub.add_parser("auto"); s.add_argument("files", nargs="+")
    s.add_argument("--out", help="reports folder (default: <app>\\reports)")
    s.add_argument("--top", type=int, default=6, help="functions to analyze in depth (default 6)")
    s.add_argument("--links", type=int, default=8, help="interesting strings to trace back to functions (default 8)")
    s.add_argument("--quick", action="store_true", help="overview, strings and procedure list only")
    s.add_argument("--no-evidence", action="store_true", help="skip the evidence bundle export")
    s.add_argument("--pattern", action="append", default=[], help="extra text to look for (repeatable)")
    s.add_argument("--arch", help="CPU for headerless raw files: x86, x86_64, arm, arm64, 6502")
    s.add_argument("--entry", help="load/entry address for raw files, e.g. 0x1000")
    s.add_argument("-r", "--recursive", action="store_true", help="recurse into folders")
    a = p.parse_args(argv)

    if a.cmd == "detect":
        import autotriage
        for f in autotriage.expand_paths(a.files):
            try:
                d = autotriage.detect(f, getattr(a, "arch", None), getattr(a, "entry", None))
                print(f"{d.label:38} open_binary args: {json.dumps({'path': d.path, **d.open_args})}")
                for n in d.notes:
                    print(f"    note: {n}")
            except OSError as e:
                print(f"{f}: cannot read ({e})")
        return 0

    if a.cmd == "auto":
        import autotriage
        paths = autotriage.expand_paths(a.files, a.recursive)
        if not paths:
            print("No files found.", file=sys.stderr)
            return 2
        opts = autotriage.Options(
            out_root=Path(a.out) if a.out else config.APP_DIR / "reports",
            top_functions=a.top, string_links=a.links, quick=a.quick, export_evidence=not a.no_evidence,
            patterns=a.pattern, raw_arch=a.arch, raw_entry=a.entry)

        async def go(c):
            res = await autotriage.analyze_files(c, paths, opts)
            return 0 if res and all(r["status"] == "complete" for r in res) else 1
        return asyncio.run(_with_client(go))

    if a.cmd == "recipes":
        recipes, problems = load_recipes(RECIPES_DIR)
        for name, r in recipes.items():
            print(f"{name:24} {r.get('description', '').strip().splitlines()[0] if r.get('description') else ''}")
        for pr in problems:
            print("PROBLEM:", pr, file=sys.stderr)
        return 0

    if a.cmd == "list":
        async def go(c):
            for t in await c.list_tools():
                if a.filter.lower() in t.name.lower() or a.filter.lower() in t.description.lower():
                    first = (t.description.strip().splitlines() or [""])[0][:85]
                    print(f"{'!' if t.destructive else ' '} {t.name:42} {first}")
        asyncio.run(_with_client(go))
        return 0

    if a.cmd == "describe":
        async def go(c):
            for t in await c.list_tools():
                if t.name == a.tool:
                    print(f"{t.name}  ({t.title})" + ("  [destructive]" if t.destructive else ""))
                    print(t.description)
                    print(json.dumps(t.input_schema, indent=2))
                    return 0
            print("No such tool", file=sys.stderr)
            return 1
        return asyncio.run(_with_client(go))

    if a.cmd == "call":
        try:
            args = json.loads(a.args)
        except json.JSONDecodeError as e:
            print(f"Arguments are not valid JSON: {e}", file=sys.stderr)
            return 2

        async def go(c):
            tool = next((t for t in await c.list_tools() if t.name == a.tool), None)
            if tool is None:
                print(f"No such tool: {a.tool}", file=sys.stderr)
                return 2
            if tool.destructive and not a.yes:
                print(f"{a.tool} is marked destructive by REA (it can modify or overwrite data). "
                      f"Re-run with --yes to allow it.", file=sys.stderr)
                return 3
            res = await c.call_tool(a.tool, args)
            journal.record(a.tool, args, res.data, res.is_error)
            print(res.pretty())
            return 1 if res.is_error else 0
        return asyncio.run(_with_client(go))

    if a.cmd == "recipe":
        recipes, _ = load_recipes(RECIPES_DIR)
        if a.name not in recipes:
            print(f"Unknown recipe {a.name!r}. Known: {', '.join(recipes) or '(none)'}", file=sys.stderr)
            return 2
        recipe = recipes[a.name]
        inputs = {i["name"]: str(i.get("default", "")) for i in recipe.get("inputs", [])}
        for kv in a.input:
            k, _, v = kv.partition("=")
            inputs[k] = v

        async def go(c):
            r = await run_recipe(c, recipe, inputs)
            return 0 if r["ok"] else 1
        return asyncio.run(_with_client(go))
    return 2
