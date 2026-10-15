"""Evidence tab: open any JSON file (evidence bundle, saved result, journal
line) and browse it as a tree."""
from __future__ import annotations

import json
from typing import Any

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

MAX_CHILDREN = 2000


class EvidenceViewer(QWidget):
    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        b = QPushButton("Open JSON file…"); b.clicked.connect(self._open); row.addWidget(b)
        self.label = QLabel("No file loaded")
        row.addWidget(self.label, 1)
        lay.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.setColumnWidth(0, 360)
        lay.addWidget(self.tree, 1)

    def _open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open JSON", "", "JSON (*.json *.jsonl);;All (*)")
        if path:
            self.load(path)

    def load(self, path: str) -> None:
        try:
            text = open(path, encoding="utf-8").read()
            try:
                data: Any = json.loads(text)
            except json.JSONDecodeError:  # maybe JSON Lines
                data = [json.loads(l) for l in text.splitlines() if l.strip()]
        except Exception as e:  # noqa: BLE001
            self.label.setText(f"Could not read {path}: {e}")
            return
        self.label.setText(path)
        self.tree.clear()
        root = QTreeWidgetItem(["(root)", ""])
        self.tree.addTopLevelItem(root)
        self._fill(root, data)
        root.setExpanded(True)

    def _fill(self, parent: QTreeWidgetItem, value: Any) -> None:
        if isinstance(value, dict):
            items = list(value.items())
        elif isinstance(value, list):
            items = [(f"[{i}]", v) for i, v in enumerate(value)]
        else:
            parent.setText(1, str(value))
            return
        for k, v in items[:MAX_CHILDREN]:
            if isinstance(v, (dict, list)):
                child = QTreeWidgetItem([str(k), f"{{{len(v)}}}" if isinstance(v, dict) else f"[{len(v)}]"])
                parent.addChild(child)
                self._fill(child, v)
            else:
                parent.addChild(QTreeWidgetItem([str(k), str(v)]))
        if len(items) > MAX_CHILDREN:
            parent.addChild(QTreeWidgetItem(["…", f"{len(items) - MAX_CHILDREN} more not shown"]))
