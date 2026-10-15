"""Recipe tab: pick a YAML recipe, fill its inputs, run it step by step."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)

from bridge import AsyncBridge
from mcp_client import ReaClient
from recipes_engine import load_recipes, run_recipe


class RecipeRunner(QWidget):
    line = Signal(str)  # safe to emit from the asyncio thread

    def __init__(self, client: ReaClient, bridge: AsyncBridge, recipes_dir: Path) -> None:
        super().__init__()
        self.client, self.bridge, self.dir = client, bridge, recipes_dir
        self.recipes: dict[str, dict] = {}
        self._inputs: dict[str, QLineEdit] = {}
        self._build()
        self.reload()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Recipe:"))
        self.combo = QComboBox()
        self.combo.currentTextChanged.connect(self._on_change)
        row.addWidget(self.combo, 1)
        b = QPushButton("Reload"); b.clicked.connect(self.reload); row.addWidget(b)
        b = QPushButton("Open recipes folder")
        b.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.dir))))
        row.addWidget(b)
        lay.addLayout(row)
        self.desc = QLabel("")
        self.desc.setWordWrap(True)
        lay.addWidget(self.desc)
        self.inputs_widget = QWidget()
        self.inputs_form = QFormLayout(self.inputs_widget)
        lay.addWidget(self.inputs_widget)
        row = QHBoxLayout()
        self.run_btn = QPushButton("Run recipe")
        self.run_btn.clicked.connect(self._run)
        row.addWidget(self.run_btn)
        row.addStretch()
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFont("Consolas", 10))
        lay.addWidget(self.out, 1)
        self.line.connect(self.out.appendPlainText)

    def reload(self) -> None:
        self.recipes, problems = load_recipes(self.dir)
        self.combo.blockSignals(True)
        self.combo.clear()
        self.combo.addItems(list(self.recipes))
        self.combo.blockSignals(False)
        self._on_change(self.combo.currentText())
        for p in problems:
            self.out.appendPlainText(f"Could not load {p}")

    def _on_change(self, name: str) -> None:
        r = self.recipes.get(name)
        while self.inputs_form.rowCount():
            self.inputs_form.removeRow(0)
        self._inputs.clear()
        if not r:
            self.desc.setText("")
            return
        self.desc.setText((r.get("description") or "").strip())
        for inp in r.get("inputs", []) or []:
            edit = QLineEdit(str(inp.get("default", "")))
            label = inp.get("label", inp["name"])
            if inp.get("path"):
                holder = QWidget()
                h = QHBoxLayout(holder); h.setContentsMargins(0, 0, 0, 0)
                h.addWidget(edit, 1)
                btn = QPushButton("…"); btn.setFixedWidth(32)
                btn.clicked.connect(lambda _=False, e=edit: self._pick(e))
                h.addWidget(btn)
                self.inputs_form.addRow(label, holder)
            else:
                self.inputs_form.addRow(label, edit)
            self._inputs[inp["name"]] = edit

    def _pick(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            edit.setText(path)

    def _run(self) -> None:
        recipe = self.recipes.get(self.combo.currentText())
        if not recipe:
            return
        inputs = {k: w.text() for k, w in self._inputs.items()}
        self.out.clear()
        self.run_btn.setEnabled(False)
        coro = run_recipe(self.client, recipe, inputs, log=self.line.emit)
        self.bridge.submit(coro, lambda res, err: self._finished(err))

    def _finished(self, err) -> None:
        if err is not None:
            self.out.appendPlainText(f"ERROR: {err}")
        self.run_btn.setEnabled(True)
