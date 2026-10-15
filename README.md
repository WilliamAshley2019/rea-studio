# REA Studio

A Windows desktop app and CLI that lets a **human** drive REA ("Reverse Engineer
Anything", morluto/rea) the way an LLM agent would: browse all MCP tools, fill
in their arguments as forms, read the JSON, chain calls, and script repeatable
workflows as recipes.

## Install and run

1. Python 3.10+ on PATH (tested design target: Python 3.13 with `mcp` 1.26 or 2.x).
2. Unzip to e.g. `C:\rea-studio\`.
3. **If pip can't reach PyPI (DNS wall):** put the wheels
   `pyside6_essentials-6.12.0-cp310-abi3-win_amd64.whl`,
   `pyside6_addons-6.12.0-cp310-abi3-win_amd64.whl` and
   `shiboken6-6.12.0-cp310-abi3-win_amd64.whl` in a `wheels\` folder next to
   `main.py`. `run.bat` then builds a venv that sees your system Python's
   `mcp`/`pyyaml` and installs PySide6 offline.
   **Otherwise** `run.bat` installs from PyPI.
4. Double-click `run.bat`. (Delete `.venv` first if an earlier attempt failed.)

On first start it writes `rea-studio.config.json` next to `main.py`. Edit it if
your paths differ:

```json
{
  "rea_root": "C:\\Users\\Administrator\\Downloads\\rea-main",
  "ghidra_install_dir": "C:\\Tools\\ghidra-master\\ghidra_12.1.2_PUBLIC_20260605\\ghidra_12.1.2_PUBLIC",
  "java_home": "C:\\Program Files\\Java\\jdk-25.0.4",
  "provider": "ghidra",
  "node": "node"
}
```
Environment variables `REA_ROOT`, `GHIDRA_INSTALL_DIR`, `JAVA_HOME`,
`REA_ANALYSIS_PROVIDER` override the file. REA Studio launches
`node <rea_root>\scripts\rea.mjs mcp` itself and passes the Ghidra/Java
variables to it, so you do not need MCP Playground running (you can keep using
both).

## Auto Analyze (start here)

Add one or more programs (or a whole folder) and press **Run auto analysis**.
REA Studio reads each file's header to decide how to open it, runs a static
triage, and writes a report folder under `reports\`. **The file is never
executed**: the pipeline only calls analysis tools, never run/instrument/device
tools.

What it detects and does:

| Detected | Handling |
|---|---|
| Windows PE (EXE/DLL, x86/x64/arm64) | open → session → overview → segments → procedures → strings → file layout and PE resources (static) → trace interesting strings back to the functions that use them → analyze the entry point and those functions → export evidence |
| .NET assembly | skips Ghidra (useless for managed code); runs the managed assembly and member inspectors instead |
| ELF, Mach-O | same native pipeline as PE |
| DOS `.com` | opens with `format=dos-com` automatically |
| APK/JAR/ZIP | opens as an archive and summarizes it |
| JavaScript/plist/map | opens it; use the Tools tab for deeper JavaScript analysis |
| Headerless raw dump | REA cannot guess the CPU. Give the CPU and entry address in the "Headerless raw file" boxes (CLI: `--arch x86 --entry 0x1000`) |
| Anything else | REA tries its own detection; if it refuses, the report says so |

Strings are sorted into categories (credential/license words, URLs, registry
keys, error messages, file paths, DLL names, debug paths, IPs/emails, version
text). Add your own words in "Extra search text" and the functions that use them
are analyzed too. Each report folder contains:

- `report.md` the readable summary (segments incl. writable+executable warnings, entry points, string categories, analyzed functions with pseudocode, a step table)
- `procedures.tsv`, `strings.tsv` complete lists (open in Excel)
- `evidence.json` REA's evidence bundle
- `raw\` the full JSON of every step (open in the Evidence tab)

A step that fails or is unavailable is recorded in the report and the run
continues. **Stop after current step** ends cleanly and still writes a partial
report. With several files, a `reports\index-*.md` table summarizes the batch.

Command line equivalents:

```
python main.py cli detect C:\castle.exe                 # what would happen, no REA needed
python main.py cli auto C:\castle.exe                   # full triage
python main.py cli auto C:\games\ -r --quick           # every program in a folder, overview only
python main.py cli auto C:\castle.exe --pattern savegame --pattern licence --top 10
```

## The tabs

**Tools** — all 193 REA tools in 14 categories (Session & navigation, Native
analysis, Annotations (write), Evidence & reconstruction, Web & browser,
JavaScript & Electron, ADB, Frida, Android, Apple, .NET, packets/signals,
firmware/formats, JEB). Filter by name, title or description. The form is
generated from the tool's real schema (`*` = required; enums are drop-downs;
booleans are unset/true/false so you never send a value you did not choose;
lists of strings/numbers are one value per line; structured values are JSON;
`…` buttons pick files). 178 tools ship examples: **"Fill from an example"**
fills the form with a known-good call. Tools REA marks **destructive** are
orange and ask for confirmation before running (untick *Confirm destructive
tools* to skip). Buttons: *Call tool*, *Copy result*, *Save result…*, and
**Copy as recipe step**. If a result says `available: false`, a banner shows
the reason.

**Recipes** — run YAML workflows from the `recipes\` folder. Pick one, fill the
inputs (`…` opens a file picker), *Run recipe*. Output streams step by step.

**Evidence** — open any JSON/JSONL file (exported evidence bundle, saved
result, a journal) as a collapsible tree.

**Console** — runs the REA CLI (`doctor --json`, `providers`, …) with the same
environment. This tab works even when the MCP connection fails.

Every tool call from the Tools tab and the CLI is appended to
`sessions\journal-YYYYMMDD.jsonl`, so you can see exactly what you did.

## Command line

```
python main.py cli list [filter]          # a leading ! marks destructive tools
python main.py cli describe TOOL          # title, description, full schema
python main.py cli call TOOL '{"pattern":"flag","mode":"literal"}'
python main.py cli call export_evidence_bundle '{"path":"C:\\x.json"}' --yes   # --yes needed for destructive tools
python main.py cli recipes
python main.py cli recipe recon_binary -i binary_path=C:\samples\a.exe -i search_pattern=flag
```
(In PowerShell use `'{\"a\":1}'` or put the JSON in a variable if quotes get eaten.)
Exit code is 0 on success, non-zero if a tool reported an error or a recipe
stopped (3 = refused a destructive tool without `--yes`). Recipes are not
gated: you chose their steps when you wrote them.

## Writing a recipe

Drop a `.yaml` in `recipes\` and press *Reload*:

```yaml
name: My recipe
description: What it does
inputs:
  - {name: target, label: Target file, path: true, default: ""}
steps:
  - tool: open_binary
    args: {path: "{input.target}"}
  - tool: search_strings
    args: {pattern: "license", mode: literal}
    save_as: hits               # later steps can use {result.hits.<key>}
    on_error: continue          # optional; default stops the recipe
```
`"{input.x}"` and `"{result.name.key.0}"` are replaced before each call. A
value that is *only* a placeholder keeps its type (number stays number).

## Tutorial 1 — "act as the agent" in five minutes

1. **Console → doctor**. Confirms REA, Ghidra and Java are found. Look for
   `native_authority`; if it fails, Ghidra-backed tools are blocked (see below).
2. **Tools → filter `session`** → `binary_session` → *Call tool*. This is the
   first thing an agent does: ask what is open.
3. Filter `list_` and call `list_documents`. Read the JSON like an agent would:
   look for `results`, `detail`, `evidence`, and `available`.
4. Pick a tool, read its description (it is written for agents, so it explains
   when to use it), fill the form, call it. Use *Copy as recipe step* on each
   good call, and paste the steps into a new recipe. You have just turned an
   investigation into something repeatable.
5. **Follow an LLM's instructions**: when an LLM says
   `call search_strings with pattern="flag"`, type `search` in the filter,
   select the tool, and enter the same arguments. Names and arguments map 1:1.

Typical native-binary chain (once the addon is built):
`search_strings` / `search_procedures` → `analyze_function` →
`procedure_pseudo_code` or `read_function_instructions` → `procedure_callers` /
`xrefs` → `read_bytes` → `export_evidence_bundle`.

## What has and has not been verified

Verified (with REA 6.4.0's real tool catalog, 193 tools, from your machine):
- Every tool's schema builds a working form, and all 203 shipped examples
  round-trip exactly (`tests\forms_real.py`).
- The app connects, lists, calls, gates destructive tools and runs recipes
  against a stand-in MCP server, on both `mcp` 1.26.0 (your version) and 2.3.0.
- The recipes use argument names confirmed in the real schemas.

Auto Analyze was additionally tested end to end: every call it makes is checked
against REA's real input schemas, and the stand-in server's replies are checked
against REA's real output schemas (`tests\auto_test.py`, `tests\gui_auto.py`).

**Not yet verified:** a real call into REA/Ghidra from this app on your
machine, and how real results look (no custom result views yet — results are
pretty-printed JSON). Open a small `.exe` with `open_binary`, run
`list_procedures`/`search_strings`, and send me the JSON to get proper views.

Auto Analyze reads results by the documented field names (`normalized_result`,
`address`, `value`, …). If real output differs somewhere, that part of the
report is thinner but nothing crashes, and `raw\` always has the full reply.
Large programs may produce very large string lists and slow steps; use
**Quick** first.

Other limits: calls are sequential and block the Call button until they return
(no cancel yet); `open_binary` on first analysis takes 30-90 s.

## Self-tests (optional, no REA needed)

```
python tests/auto_test.py                # Auto Analyze end to end against a stand-in REA
QT_QPA_PLATFORM=offscreen python tests/forms_real.py
```

## Self-test of the GUI (optional)

```
QT_QPA_PLATFORM=offscreen python tests/gui_smoke.py
```
needs `server_command`/`server_args` in the config pointing at
`tests\fake_rea_server.py`. `python tests/forms_real.py` needs no server.

## Next passes

Result views for function lists/strings/xrefs (needs real sample output),
project/investigation tab, recipe editor, tool favorites, cancel button,
PyInstaller `.exe`, in-app tutorial mode that highlights the next tool to call.
