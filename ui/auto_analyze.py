"""Auto Analyze tab: add exe/dll files (or a folder), see what was detected,
press Run, get a report folder per file."""
from __future__ import annotations

import os
import threading
from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

import autotriage
from bridge import AsyncBridge
from mcp_client import ReaClient


class AutoAnalyzeTab(QWidget):
    line = Signal(str)

    def __init__(self, client: ReaClient, bridge: AsyncBridge, reports_dir: Path) -> None:
        super().__init__()
        self.client, self.bridge, self.reports_dir = client, bridge, reports_dir
        self._cancel: threading.Event | None = None
        self._last_report = ""
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Pick one or more programs. REA Studio works out how to open each one, runs a static "
                             "triage (the file is never executed) and writes a report folder."))
        self.files = QListWidget()
        self.files.setMaximumHeight(150)
        lay.addWidget(self.files)

        row = QHBoxLayout()
        for text, fn in (("Add files…", self._add_files), ("Add folder…", self._add_folder),
                         ("Remove selected", self._remove), ("Clear", self.files.clear)):
            b = QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)

        grid = QGridLayout()
        self.quick = QCheckBox("Quick (skip function analysis)")
        self.evidence = QCheckBox("Export evidence bundle"); self.evidence.setChecked(True)
        self.top = QSpinBox(); self.top.setRange(0, 50); self.top.setValue(6)
        self.links = QSpinBox(); self.links.setRange(0, 50); self.links.setValue(8)
        self.patterns = QLineEdit(); self.patterns.setPlaceholderText("extra text to look for, comma-separated (e.g. castle, savegame)")
        self.arch = QComboBox(); self.arch.addItems(["", "x86", "x86_64", "arm", "arm64", "6502"])
        self.entry = QLineEdit(); self.entry.setPlaceholderText("0x1000")
        self.out = QLineEdit(str(self.reports_dir))
        browse = QPushButton("…"); browse.setFixedWidth(32); browse.clicked.connect(self._pick_out)
        grid.addWidget(self.quick, 0, 0, 1, 2); grid.addWidget(self.evidence, 0, 2, 1, 2)
        grid.addWidget(QLabel("Functions to analyze:"), 1, 0); grid.addWidget(self.top, 1, 1)
        grid.addWidget(QLabel("Strings to trace to functions:"), 1, 2); grid.addWidget(self.links, 1, 3)
        grid.addWidget(QLabel("Extra search text:"), 2, 0); grid.addWidget(self.patterns, 2, 1, 1, 3)
        grid.addWidget(QLabel("Headerless raw file only, CPU / entry:"), 3, 0)
        grid.addWidget(self.arch, 3, 1); grid.addWidget(self.entry, 3, 2, 1, 2)
        grid.addWidget(QLabel("Reports folder:"), 4, 0); grid.addWidget(self.out, 4, 1, 1, 2); grid.addWidget(browse, 4, 3)
        lay.addLayout(grid)

        row = QHBoxLayout()
        self.run_btn = QPushButton("Run auto analysis"); self.run_btn.clicked.connect(self._run); row.addWidget(self.run_btn)
        self.stop_btn = QPushButton("Stop after current step"); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop); row.addWidget(self.stop_btn)
        b = QPushButton("Open last report"); b.clicked.connect(self._open_report); row.addWidget(b)
        b = QPushButton("Open reports folder"); b.clicked.connect(self._open_folder); row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)

        self.log = QPlainTextEdit(); self.log.setReadOnly(True); self.log.setFont(QFont("Consolas", 10))
        lay.addWidget(self.log, 1)
        self.line.connect(self.log.appendPlainText)

    # ---- file list ----------------------------------------------------
    def _add_paths(self, paths: list[str]) -> None:
        existing = {self.files.item(i).data(1) for i in range(self.files.count())}
        for p in autotriage.expand_paths(paths):
            if p in existing:
                continue
            try:
                d = autotriage.detect(p, self.arch.currentText() or None, self.entry.text().strip() or None)
                item = QListWidgetItem(f"{os.path.basename(p)}   —   {d.label}   ({p})")
                item.setToolTip("\n".join(d.notes) or d.label)
            except OSError as e:
                item = QListWidgetItem(f"{p}   —   cannot read: {e}")
            item.setData(1, p)
            self.files.addItem(item)

    def _add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Select programs to analyze", "",
                                                "Programs (*.exe *.dll *.sys *.ocx *.drv *.scr *.so *.dylib *.com);;All files (*)")
        self._add_paths(paths)

    def _add_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select a folder (programs inside are added)")
        if d:
            self._add_paths([d])

    def _remove(self) -> None:
        for it in self.files.selectedItems():
            self.files.takeItem(self.files.row(it))

    def _pick_out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Reports folder")
        if d:
            self.out.setText(d)

    # ---- run ----------------------------------------------------------
    def _run(self) -> None:
        paths = [self.files.item(i).data(1) for i in range(self.files.count())]
        if not paths:
            self.log.appendPlainText("Add at least one file first.")
            return
        if not self.client.connected:
            self.log.appendPlainText("Not connected to REA yet. Wait for the status line at the top, or click Reconnect.")
            return
        self._cancel = threading.Event()
        opts = autotriage.Options(
            out_root=Path(self.out.text().strip() or str(self.reports_dir)),
            top_functions=self.top.value(), string_links=self.links.value(), quick=self.quick.isChecked(),
            export_evidence=self.evidence.isChecked(),
            patterns=[p.strip() for p in self.patterns.text().split(",") if p.strip()],
            raw_arch=self.arch.currentText() or None, raw_entry=self.entry.text().strip() or None,
            cancel=self._cancel)
        self.log.clear()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.bridge.submit(autotriage.analyze_files(self.client, paths, opts, log=self.line.emit), self._done)

    def _done(self, results, err) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if err is not None:
            self.log.appendPlainText(f"\nERROR: {err}")
            return
        done = [r for r in results if r.get("report")]
        if done:
            self._last_report = done[-1]["report"]
        self.log.appendPlainText(f"\nFinished {len(results)} file(s). Use 'Open last report' to read the result.")

    def _stop(self) -> None:
        if self._cancel:
            self._cancel.set()
            self.log.appendPlainText("Stopping after the current step…")

    def _open_report(self) -> None:
        if self._last_report and os.path.exists(self._last_report):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._last_report))
        else:
            self.log.appendPlainText("No report yet.")

    def _open_folder(self) -> None:
        p = Path(self.out.text().strip() or str(self.reports_dir))
        p.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))
