"""Turn a JSON-Schema `inputSchema` into a Qt form and back into arguments.

Handles what REA's real schemas use: local `$ref` into `$defs`, `anyOf`/`oneOf`
(nullable and const unions), enums, arrays of scalars (one per line), and
falls back to a JSON box for genuinely structured values.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLineEdit, QPlainTextEdit,
    QPushButton, QWidget,
)

MISSING = object()
PATH_HINTS = ("path", "file", "dir", "folder")


# ---- schema handling (pure, no Qt) --------------------------------------
def deref(s: Any, root: dict, _depth: int = 0) -> dict:
    """Resolve local $ref chains; sibling keys (description, default) win."""
    while isinstance(s, dict) and "$ref" in s and _depth < 32:
        ref = s["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            break
        cur: Any = root
        try:
            for part in ref[2:].split("/"):
                cur = cur[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError, IndexError):
            break
        if not isinstance(cur, dict):
            break
        s = {**cur, **{k: v for k, v in s.items() if k != "$ref"}}
        _depth += 1
    return s if isinstance(s, dict) else {}


@dataclass
class Spec:
    kind: str                      # enum bool int num text lines json
    desc: str | None = None
    default: Any = None
    values: list = field(default_factory=list)
    item_type: str | None = None
    hint: str = ""
    nullable: bool = False


def _object_hint(s: dict) -> str:
    props = list((s.get("properties") or {}).keys())
    return ("JSON object with: " + ", ".join(props[:8]) + ("…" if len(props) > 8 else "")) if props else "JSON value"


def spec_of(s: Any, root: dict, outer_desc: str | None = None, depth: int = 0) -> Spec:
    s = deref(s, root)
    desc = s.get("description") or outer_desc
    default = s.get("default")
    if depth > 6:
        return Spec("json", desc, default, hint="JSON value")
    if "enum" in s:
        return Spec("enum", desc, default, values=list(s["enum"]))
    if "const" in s:
        return Spec("enum", desc, default, values=[s["const"]])
    for key in ("anyOf", "oneOf"):
        if key in s:
            subs = [deref(x, root) for x in s[key]]
            nn = [x for x in subs if x.get("type") != "null"]
            if nn and all("const" in x or "enum" in x for x in nn):
                vals: list = []
                for x in nn:
                    vals += x["enum"] if "enum" in x else [x["const"]]
                return Spec("enum", desc, default, values=vals)
            if len(nn) == 1:
                inner = spec_of(nn[0], root, desc, depth + 1)
                if inner.default is None:
                    inner.default = default
                inner.nullable = len(nn) < len(subs)
                return inner
            return Spec("json", desc, default, hint="JSON value (one of several shapes; see the description)")
    t = s.get("type")
    if isinstance(t, list):
        nn_t = [x for x in t if x != "null"]
        t = nn_t[0] if len(nn_t) == 1 else None
    if t == "boolean":
        return Spec("bool", desc, default)
    if t == "integer":
        return Spec("int", desc, default)
    if t == "number":
        return Spec("num", desc, default)
    if t == "string":
        return Spec("text", desc, default)
    if t == "array":
        it = deref(s.get("items") or {}, root)
        itype = it.get("type")
        simple = itype in ("string", "integer", "number") and not any(k in it for k in ("enum", "anyOf", "oneOf"))
        if simple:
            return Spec("lines", desc, default, item_type=itype)
        return Spec("json", desc, default, hint="JSON array")
    if t == "object":
        return Spec("json", desc, default, hint=_object_hint(s))
    return Spec("json", desc, default, hint="JSON value")


# ---- Qt field -------------------------------------------------------------
class _Field:
    def __init__(self, name: str, schema: Any, required: bool, root: dict):
        self.name, self.required = name, required
        self.spec = spec = spec_of(schema, root)
        self.kind = spec.kind
        d = spec.default
        if self.kind == "enum":
            w = QComboBox()
            self._values = {str(v): v for v in spec.values}
            if not required:
                w.addItem("")
            w.addItems(list(self._values))
            if d is not None and str(d) in self._values:
                w.setCurrentText(str(d))
        elif self.kind == "bool":
            w = QComboBox()
            w.addItems(["(unset)", "true", "false"])
            w.setCurrentIndex(1 if d is True else 2 if d is False else 0)
        elif self.kind in ("int", "num", "text"):
            w = QLineEdit()
            if d is not None:
                w.setText(str(d))
        else:
            w = QPlainTextEdit()
            w.setMaximumHeight(90)
            w.setPlaceholderText("one value per line (or a JSON array)" if self.kind == "lines" else spec.hint)
            if d is not None:
                w.setPlainText(json.dumps(d) if self.kind == "json" else "\n".join(map(str, d)))
        self.widget = w
        if spec.desc:
            w.setToolTip(spec.desc)
        self.row: QWidget = w
        if self.kind == "text" and (any(h in name.lower() for h in PATH_HINTS)
                                    or "filesystem path" in (spec.desc or "").lower()):
            holder = QWidget()
            lay = QHBoxLayout(holder)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(w, 1)
            btn = QPushButton("…")
            btn.setFixedWidth(32)
            btn.clicked.connect(self._browse)
            lay.addWidget(btn)
            self.row = holder

    def _browse(self) -> None:
        desc = (self.spec.desc or "").lower()
        if "dir" in self.name.lower() or "folder" in self.name.lower():
            path = QFileDialog.getExistingDirectory(self.widget, "Select folder")
        elif re.search(r"export|output|write|save|destination", desc):
            path, _ = QFileDialog.getSaveFileName(self.widget, "Choose file to write")
        else:
            path, _ = QFileDialog.getOpenFileName(self.widget, "Select file")
        if path:
            self.widget.setText(path)

    def value(self) -> Any:
        k, w = self.kind, self.widget
        if k == "enum":
            txt = w.currentText()
            return MISSING if txt == "" else self._values.get(txt, txt)
        if k == "bool":
            return MISSING if w.currentIndex() == 0 else w.currentIndex() == 1
        if k in ("json", "lines"):
            txt = w.toPlainText().strip()
            if not txt:
                return MISSING
            if k == "json" or txt.startswith("["):
                try:
                    return json.loads(txt)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{self.name}: invalid JSON ({e})")
            out = []
            for line in (l.strip() for l in txt.splitlines()):
                if not line:
                    continue
                try:
                    out.append(int(line, 0) if self.spec.item_type == "integer"
                               else float(line) if self.spec.item_type == "number" else line)
                except ValueError:
                    raise ValueError(f"{self.name}: '{line}' is not a valid {self.spec.item_type}")
            return out
        txt = w.text().strip()
        if not txt:
            return MISSING
        try:
            if k == "int":
                return int(txt, 0)
            if k == "num":
                return float(txt)
        except ValueError:
            raise ValueError(f"{self.name}: '{txt}' is not a valid number")
        return txt

    def set_value(self, v: Any) -> None:
        k, w = self.kind, self.widget
        if k == "enum":
            w.setCurrentText(str(v))
        elif k == "bool":
            w.setCurrentIndex(1 if v else 2)
        elif k == "lines" and isinstance(v, list) and v and all(not isinstance(x, (dict, list)) for x in v):
            w.setPlainText("\n".join(str(x) for x in v))
        elif k in ("json", "lines"):
            w.setPlainText(json.dumps(v))
        else:
            w.setText(str(v))


class SchemaForm(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._layout = QFormLayout(self)
        self._fields: list[_Field] = []
        self.examples: list[dict] = []

    def build(self, schema: dict) -> None:
        while self._layout.rowCount():
            self._layout.removeRow(0)
        self._fields.clear()
        schema = schema or {}
        props = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        self.examples = [e for e in (schema.get("examples") or []) if isinstance(e, dict)]
        names = sorted(props, key=lambda n: (n not in required,))  # required first, stable
        for name in names:
            f = _Field(name, props[name], name in required, schema)
            self._layout.addRow(name + (" *" if name in required else ""), f.row)
            self._fields.append(f)

    def collect(self) -> dict[str, Any]:
        args: dict[str, Any] = {}
        for f in self._fields:
            v = f.value()
            if v is MISSING:
                if f.required and f.spec.nullable:
                    args[f.name] = None  # required but nullable: blank means null
                    continue
                if f.required:
                    raise ValueError(f"{f.name} is required")
                continue
            args[f.name] = v
        return args

    def set_values(self, args: dict[str, Any]) -> None:
        for f in self._fields:
            if f.name in args and args[f.name] is not None:
                f.set_value(args[f.name])
