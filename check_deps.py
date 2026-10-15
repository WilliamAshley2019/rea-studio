"""List every package REA Studio needs that is missing from THIS Python, with
the PyPI page to download each from (pure-Python wheels are py3-none-any).

  .venv\\Scripts\\python check_deps.py
"""
import sys
from importlib import metadata

try:
    from pip._vendor.packaging.requirements import Requirement
except Exception:  # pragma: no cover
    from packaging.requirements import Requirement  # type: ignore

ROOTS = ["mcp>=1.2", "pyyaml", "PySide6-Essentials"]


def walk(req_str, seen, missing, parent):
    req = Requirement(req_str)
    if req.marker is not None and not req.marker.evaluate({"extra": ""}):
        return
    key = req.name.lower().replace("_", "-")
    if key in seen:
        return
    seen.add(key)
    try:
        dist = metadata.distribution(req.name)
    except metadata.PackageNotFoundError:
        missing.append((req.name, parent))
        return
    for sub in dist.requires or []:
        walk(sub, seen, missing, req.name)


seen, missing = set(), []
for r in ROOTS:
    walk(r, seen, missing, "(app)")

print(f"Python {sys.version.split()[0]} at {sys.executable}")
if not missing:
    print("All required packages are installed.")
    sys.exit(0)
print(f"{len(missing)} package(s) missing:")
for name, parent in missing:
    print(f"  {name:28} needed by {parent:18} https://pypi.org/project/{name}/#files")
print("\nDownload each one's wheel into the wheels folder, then run run.bat again.")
sys.exit(1)
