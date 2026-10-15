"""REA Studio — a human-facing Windows app for REA.

  python main.py          start the GUI
  python main.py cli ...  headless command line (see cli.py)
"""
from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        import cli
        return cli.main(sys.argv[2:])

    from PySide6.QtWidgets import QApplication

    import config
    from bridge import AsyncBridge
    from mcp_client import ReaClient
    from ui.main_window import MainWindow

    config.ensure_config_file()
    cfg = config.load()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    bridge = AsyncBridge()
    client = ReaClient.from_config(cfg)
    window = MainWindow(cfg, client, bridge)
    window.show()
    window.connect_to_rea()
    code = app.exec()
    bridge.shutdown()
    return code


if __name__ == "__main__":
    sys.exit(main())
