"""Console tab: run the REA CLI (rea.mjs <args>) and show its output."""
from __future__ import annotations

from PySide6.QtCore import QProcess, QProcessEnvironment
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

import config


class ConsoleTab(QWidget):
    QUICK = [("doctor", "doctor --json"),
             ("doctor (ghidra)", "doctor --provider ghidra --json"),
             ("providers", "providers")]

    def __init__(self, cfg: dict) -> None:
        super().__init__()
        self.cfg = cfg
        self.proc: QProcess | None = None
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Runs: node <rea-root>\\scripts\\rea.mjs <your arguments>"))
        row = QHBoxLayout()
        for label, cmd in self.QUICK:
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, c=cmd: self.run(c))
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        row = QHBoxLayout()
        self.cmd = QLineEdit()
        self.cmd.setPlaceholderText("e.g. doctor --json")
        self.cmd.returnPressed.connect(lambda: self.run(self.cmd.text()))
        row.addWidget(self.cmd, 1)
        go = QPushButton("Run"); go.clicked.connect(lambda: self.run(self.cmd.text())); row.addWidget(go)
        stop = QPushButton("Stop"); stop.clicked.connect(self.stop); row.addWidget(stop)
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFont("Consolas", 10))
        lay.addWidget(self.out, 1)

    def update_config(self, cfg: dict) -> None:
        self.cfg = cfg

    def run(self, text: str) -> None:
        if self.proc and self.proc.state() != QProcess.NotRunning:
            self.out.appendPlainText("(a command is already running — press Stop first)")
            return
        user_args = QProcess.splitCommand(text.strip()) if text.strip() else []
        node = self.cfg.get("node", "node")
        args = [config.launcher_path(self.cfg)] + user_args
        env = QProcessEnvironment.systemEnvironment()
        for k, v in config.server_env(self.cfg).items():
            env.insert(k, v)
        self.proc = QProcess(self)
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.errorOccurred.connect(lambda e: self.out.appendPlainText(f"[process error: {e}]"))
        self.proc.finished.connect(lambda code, _s: self.out.appendPlainText(f"\n[exit code {code}]"))
        self.out.appendPlainText(f"\n> {node} rea.mjs {' '.join(user_args)}")
        self.proc.start(node, args)

    def _read(self) -> None:
        data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.out.insertPlainText(data)
        self.out.ensureCursorVisible()

    def stop(self) -> None:
        if self.proc and self.proc.state() != QProcess.NotRunning:
            self.proc.kill()
