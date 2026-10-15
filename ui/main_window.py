from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMainWindow, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

import config
from bridge import AsyncBridge
from mcp_client import ReaClient
from ui.auto_analyze import AutoAnalyzeTab
from ui.console import ConsoleTab
from ui.evidence_viewer import EvidenceViewer
from ui.recipe_runner import RecipeRunner
from ui.tool_browser import ToolBrowser


class MainWindow(QMainWindow):
    def __init__(self, cfg: dict, client: ReaClient, bridge: AsyncBridge) -> None:
        super().__init__()
        self.cfg, self.client, self.bridge = cfg, client, bridge
        self.setWindowTitle("REA Studio")
        self.resize(1400, 900)

        central = QWidget()
        lay = QVBoxLayout(central)
        top = QHBoxLayout()
        self.status = QLabel("Starting…")
        top.addWidget(self.status, 1)
        self.reconnect_btn = QPushButton("Reconnect")
        self.reconnect_btn.clicked.connect(self.connect_to_rea)
        top.addWidget(self.reconnect_btn)
        lay.addLayout(top)

        self.tabs = QTabWidget()
        self.auto = AutoAnalyzeTab(client, bridge, config.APP_DIR / "reports")
        self.tool_browser = ToolBrowser(client, bridge)
        self.recipes = RecipeRunner(client, bridge, config.APP_DIR / "recipes")
        self.evidence = EvidenceViewer()
        self.console = ConsoleTab(cfg)
        self.tabs.addTab(self.auto, "Auto Analyze")
        self.tabs.addTab(self.tool_browser, "Tools")
        self.tabs.addTab(self.recipes, "Recipes")
        self.tabs.addTab(self.evidence, "Evidence")
        self.tabs.addTab(self.console, "Console")
        lay.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

    def connect_to_rea(self) -> None:
        self.status.setText("Connecting to REA (this takes a few seconds)…")
        self.reconnect_btn.setEnabled(False)

        async def go():
            await self.client.start()
            return await self.client.list_tools()

        def done(tools, err):
            self.reconnect_btn.setEnabled(True)
            if err is not None:
                self.status.setText(f"Not connected: {err}  — the Console tab still works.")
                return
            self.tool_browser.load_tools(tools)
            self.status.setText(f"Connected to REA — {len(tools)} tools")

        self.bridge.submit(go(), done)

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self.bridge.run_sync(self.client.stop(), timeout=12)
        except Exception:  # noqa: BLE001
            pass
        super().closeEvent(event)
