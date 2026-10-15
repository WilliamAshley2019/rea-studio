"""Tool browser: categorized tool tree, schema-driven form, examples, result pane."""
from __future__ import annotations

import json

import yaml
from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

import journal
from bridge import AsyncBridge
from categories import ORDER, category_of
from mcp_client import ReaClient, ToolDef
from ui.forms import SchemaForm

WARN = QColor("#b36b00")


class ToolBrowser(QWidget):
    def __init__(self, client: ReaClient, bridge: AsyncBridge) -> None:
        super().__init__()
        self.client, self.bridge = client, bridge
        self.tools: list[ToolDef] = []
        self._current: ToolDef | None = None
        self._build()

    def _build(self) -> None:
        split = QSplitter(Qt.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, title or description…")
        self.search.textChanged.connect(self._populate)
        ll.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemSelectionChanged.connect(self._on_select)
        ll.addWidget(self.tree, 1)
        self.count = QLabel("")
        ll.addWidget(self.count)
        legend = QLabel("Orange = REA marks the tool destructive")
        legend.setStyleSheet("color: #b36b00;")
        ll.addWidget(legend)
        split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        self.title = QLabel("Select a tool")
        f = self.title.font(); f.setPointSize(f.pointSize() + 3); f.setBold(True)
        self.title.setFont(f)
        rl.addWidget(self.title)
        self.badges = QLabel("")
        self.badges.setWordWrap(True)
        rl.addWidget(self.badges)
        self.desc = QLabel("")
        self.desc.setWordWrap(True)
        self.desc.setTextInteractionFlags(Qt.TextSelectableByMouse)
        desc_scroll = QScrollArea()
        desc_scroll.setWidgetResizable(True)
        desc_scroll.setWidget(self.desc)
        desc_scroll.setMaximumHeight(120)
        rl.addWidget(desc_scroll)
        line = QFrame(); line.setFrameShape(QFrame.HLine)
        rl.addWidget(line)

        self.examples = QComboBox()
        self.examples.setVisible(False)
        self.examples.activated.connect(self._fill_example)
        rl.addWidget(self.examples)

        self.form = SchemaForm()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.form)
        scroll.setMinimumHeight(230)
        rl.addWidget(scroll, 2)

        row = QHBoxLayout()
        self.call_btn = QPushButton("Call tool")
        self.call_btn.setEnabled(False)
        self.call_btn.clicked.connect(self._call)
        row.addWidget(self.call_btn)
        self.confirm = QCheckBox("Confirm destructive tools")
        self.confirm.setChecked(True)
        row.addWidget(self.confirm)
        b = QPushButton("Copy result")
        b.clicked.connect(lambda: QApplication.clipboard().setText(self.result.toPlainText()))
        row.addWidget(b)
        b = QPushButton("Save result…"); b.clicked.connect(self._save); row.addWidget(b)
        b = QPushButton("Copy as recipe step"); b.clicked.connect(self._copy_step); row.addWidget(b)
        row.addStretch()
        rl.addLayout(row)

        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("color: #b36b00; font-weight: bold;")
        rl.addWidget(self.banner)

        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setFont(QFont("Consolas", 10))
        rl.addWidget(self.result, 3)
        split.addWidget(right)
        split.setSizes([340, 960])

        outer = QVBoxLayout(self)
        outer.addWidget(split)

    # ---- tree ------------------------------------------------------
    def load_tools(self, tools: list[ToolDef]) -> None:
        self.tools = tools
        self._populate()

    def _populate(self) -> None:
        needle = self.search.text().strip().lower()
        self.tree.clear()
        groups: dict[str, QTreeWidgetItem] = {}
        shown = 0
        for t in self.tools:
            hay = f"{t.name} {t.title} {t.description}".lower()
            if needle and needle not in hay:
                continue
            cat = category_of(t.name)
            if cat not in groups:
                groups[cat] = QTreeWidgetItem([cat])
            child = QTreeWidgetItem([t.name])
            child.setData(0, Qt.UserRole, t)
            child.setToolTip(0, t.title or t.name)
            if t.destructive:
                child.setForeground(0, QBrush(WARN))
            groups[cat].addChild(child)
            shown += 1
        for cat in ORDER:
            if cat in groups:
                groups[cat].setText(0, f"{cat}  ({groups[cat].childCount()})")
                self.tree.addTopLevelItem(groups[cat])
        if needle:
            self.tree.expandAll()
        self.count.setText(f"{shown} of {len(self.tools)} tools")

    def _on_select(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        tool = items[0].data(0, Qt.UserRole)
        if not isinstance(tool, ToolDef):
            return
        self._current = tool
        self.title.setText(f"{tool.title}  ·  {tool.name}" if tool.title else tool.name)
        self.desc.setText(tool.description)
        bits = []
        if tool.destructive:
            bits.append("<span style='color:#b36b00'><b>Destructive</b> — can modify or overwrite data</span>")
        if tool.read_only:
            bits.append("read-only")
        if tool.open_world:
            bits.append("reaches outside the analysis session (devices, files, network)")
        self.badges.setText(" · ".join(bits))
        self.form.build(tool.input_schema)
        self.examples.clear()
        if tool.examples:
            self.examples.addItem(f"Fill from an example ({len(tool.examples)})…")
            for ex in tool.examples:
                self.examples.addItem(json.dumps(ex)[:110])
        self.examples.setVisible(bool(tool.examples))
        self.banner.setText("")
        self.call_btn.setEnabled(True)

    def _fill_example(self, index: int) -> None:
        if index > 0 and self._current and index - 1 < len(self._current.examples):
            self.form.build(self._current.input_schema)
            self.form.set_values(self._current.examples[index - 1])

    # ---- calling ---------------------------------------------------
    def _call(self) -> None:
        if not self._current:
            return
        try:
            args = self.form.collect()
        except ValueError as e:
            self.result.setPlainText(f"Fix the form: {e}")
            return
        name = self._current.name
        if self._current.destructive and self.confirm.isChecked():
            ok = QMessageBox.question(
                self, "Destructive tool",
                f"REA marks {name} as destructive (it can modify or overwrite data).\n\n"
                f"Arguments:\n{json.dumps(args, indent=2)[:900]}\n\nCall it?")
            if ok != QMessageBox.Yes:
                return
        self.call_btn.setEnabled(False)
        self.banner.setText("")
        self.result.setPlainText(f"Calling {name}…\n{json.dumps(args, indent=2)}")

        def done(res, err):
            self.call_btn.setEnabled(True)
            if err is not None:
                self.result.setPlainText(f"ERROR: {err}")
                return
            journal.record(name, args, res.data, res.is_error)
            note = journal.availability_note(res.data)
            if note:
                self.banner.setText(note)
            elif res.is_error:
                self.banner.setText("The server reported an error for this call.")
            self.result.setPlainText(res.pretty())

        self.bridge.submit(self.client.call_tool(name, args), done)

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save result", "result.json", "JSON (*.json);;All (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.result.toPlainText())

    def _copy_step(self) -> None:
        if not self._current:
            return
        try:
            args = self.form.collect()
        except ValueError as e:
            self.result.setPlainText(f"Fix the form: {e}")
            return
        QApplication.clipboard().setText(
            yaml.safe_dump([{"tool": self._current.name, "args": args}], sort_keys=False))
        self.banner.setText("Recipe step copied to clipboard — paste it into a recipes/*.yaml file.")
