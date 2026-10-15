"""
Batch walkthrough: run a named recipe against every binary in a folder.
Produces one JSON report per binary plus a Markdown summary, then
optionally opens everything in Notepad++.

  python batch_walkthrough.py <recipe> <binary_folder> <output_folder> [--open]

Examples:
  python batch_walkthrough.py triage_packer C:\\samples C:\\out\\triage --open
  python batch_walkthrough.py reverse_password_check C:\\crackmes C:\\out\\pw
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from mcp_client import ReaClient
from recipes_engine import load_recipes, run_recipe

BINARY_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi", ".so", ".bin"}

DEFAULT_INPUTS = {
    "triage_packer":           {},
    "reverse_password_check":  {"success_hint": "Great work|Correct|Congrats|Good work|Success",
                                 "failure_hint": "No luck|Incorrect|Wrong|Try again|Bad"},
    "recon_binary":            {"search_pattern": "http"},
    "recon_binary_full":       {"search_pattern": "http"},
    "inventory_binary":        {},
    "find_entry_points":       {},
    "find_crypto_and_packing": {},
    "find_interesting_strings": {},
}

NOTEPADPP = r"C:\Program Files\Notepad++\notepad++.exe"


def render_summary(binary: Path, recipe_name: str, results: dict, log_lines: list[str]) -> str:
    """Build a single human-readable Markdown document from the run."""
    md = []
    md.append(f"# {binary.name}")
    md.append("")
    md.append(f"- **Path:** `{binary}`")
    md.append(f"- **Recipe:** `{recipe_name}`")
    md.append(f"- **Size:** {binary.stat().st_size:,} bytes")
    md.append("")
    md.append("---")
    md.append("")
    for name, data in results.items():
        md.append(f"## {name.replace('_', ' ').title()}")
        md.append("")
        if isinstance(data, dict):
            # For key-value responses, print a compact summary first.
            summary_bits = []
            for key in ("available", "code", "reason", "detail", "count", "total"):
                if key in data:
                    summary_bits.append(f"**{key}**: `{data[key]}`")
            if summary_bits:
                md.append(" · ".join(summary_bits))
                md.append("")
            md.append("```json")
            md.append(json.dumps(data, indent=2, default=str)[:8000])
            md.append("```")
        elif isinstance(data, list):
            md.append(f"_{len(data)} entries_")
            md.append("")
            md.append("```json")
            md.append(json.dumps(data, indent=2, default=str)[:8000])
            md.append("```")
        else:
            md.append("```")
            md.append(str(data)[:4000])
            md.append("```")
        md.append("")
    if log_lines:
        md.append("---")
        md.append("")
        md.append("## Full Log")
        md.append("")
        md.append("```")
        md.append("\n".join(log_lines))
        md.append("```")
        md.append("")
    return "\n".join(md)


def open_in_notepadpp(paths: list[str]) -> None:
    """Open all paths in Notepad++ in a single window. Falls back to notepad."""
    if not paths:
        return
    if Path(NOTEPADPP).exists():
        exe = NOTEPADPP
    else:
        exe = "notepad"
    # Notepad++ accepts multiple files; -nosession keeps it from restoring prior tabs.
    args = [exe]
    if exe == NOTEPADPP:
        args.append("-nosession")
    args.extend(str(p) for p in paths if Path(p).exists())
    if len(args) <= 1:
        return
    try:
        # CREATE_NEW_PROCESS_GROUP keeps the shell usable.
        subprocess.Popen(args, creationflags=0x00000200)
    except Exception as e:
        print(f"Could not open Notepad++: {e}")


async def main(recipe_name: str, src: str, out: str, do_open: bool) -> int:
    src_path = Path(src).resolve()
    out_path = Path(out).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    recipes, problems = load_recipes(config.APP_DIR / "recipes")
    for p in problems:
        print(f"recipe problem: {p}")

    recipe = recipes.get(recipe_name)
    if recipe is None:
        print(f"Recipe {recipe_name!r} not found. Known: {', '.join(recipes)}")
        return 2

    binaries = [
        p for p in src_path.rglob("*")
        if p.is_file() and p.suffix.lower() in BINARY_EXTS
    ]
    if not binaries:
        print(f"No binaries found in {src_path}")
        return 1

    print(f"Recipe: {recipe_name}")
    print(f"Binaries: {len(binaries)}")
    print(f"Output: {out_path}")

    cfg = config.load()
    index = []
    files_to_open: list[str] = []

    async with ReaClient.from_config(cfg) as client:
        for i, binary in enumerate(binaries, 1):
            bin_out = out_path / binary.name
            bin_out.mkdir(exist_ok=True)
            log_path = bin_out / "run.log"
            summary_path = bin_out / "summary.md"
            print(f"\n[{i}/{len(binaries)}] {binary.name}")

            base_inputs = dict(DEFAULT_INPUTS.get(recipe_name, {}))
            base_inputs["binary_path"] = str(binary)

            log_lines: list[str] = []
            with open(log_path, "w", encoding="utf-8") as logf:
                def log(line: str) -> None:
                    log_lines.append(line)
                    logf.write(line + "\n")
                    logf.flush()

                try:
                    result = await run_recipe(client, recipe, base_inputs, log=log)
                    status = "ok" if result["ok"] else "partial"
                    print(f"  → {status}")

                    # Save each captured result as its own JSON
                    for name, data in result["results"].items():
                        (bin_out / f"{name}.json").write_text(
                            json.dumps(data, indent=2, default=str),
                            encoding="utf-8",
                        )

                    # Build the human-readable summary
                    md = render_summary(binary, recipe_name, result["results"], log_lines)
                    summary_path.write_text(md, encoding="utf-8")
                    files_to_open.append(str(summary_path))

                    index.append({
                        "binary": str(binary),
                        "status": status,
                        "output_dir": str(bin_out),
                        "summary": str(summary_path),
                        "results": list(result["results"].keys()),
                    })
                except Exception as e:
                    print(f"  → ERROR: {e}")
                    log(f"ERROR: {e}")
                    index.append({"binary": str(binary), "status": "error", "error": str(e)})

    index_path = out_path / "index.json"
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(f"\nDone. Index: {index_path}")
    print(f"Summaries: {len(files_to_open)} file(s)")

    if do_open and files_to_open:
        print("Opening summaries in Notepad++...")
        open_in_notepadpp(files_to_open)

    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    do_open = "--open" in sys.argv
    if len(args) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(asyncio.run(main(args[0], args[1], args[2], do_open)))