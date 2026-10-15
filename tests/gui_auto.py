"""Offscreen test of the Auto Analyze tab. Needs the config to point at tests/fake_native_server.py.
QT_QPA_PLATFORM=offscreen python tests/gui_auto.py [screenshot.png]"""
import struct, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from PySide6.QtWidgets import QApplication
import config
from bridge import AsyncBridge
from mcp_client import ReaClient
from ui.main_window import MainWindow

def pe():
    dos = bytearray(64); dos[:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 0x80)
    return bytes(dos) + b"\0" * 64 + b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22) + bytes(240) + b"\0" * 64

app = QApplication([]); app.setStyle("Fusion")
cfg = config.load(); bridge = AsyncBridge(); client = ReaClient.from_config(cfg)
w = MainWindow(cfg, client, bridge); w.resize(1200, 820); w.show(); w.connect_to_rea()
def pump(cond, secs=40):
    end = time.time() + secs
    while time.time() < end and not cond():
        app.processEvents(); time.sleep(0.02)
    assert cond(), "timeout"
pump(lambda: "Connected" in w.status.text()); print("STATUS:", w.status.text())
tab = w.auto
assert w.tabs.tabText(0) == "Auto Analyze"
with tempfile.TemporaryDirectory() as t:
    exe = Path(t) / "castle.exe"; exe.write_bytes(pe())
    tab._add_paths([str(exe)]); print("LIST:", tab.files.item(0).text())
    tab.out.setText(str(Path(t) / "reports")); tab.patterns.setText("savegame")
    tab._run(); pump(lambda: tab.run_btn.isEnabled() and "Finished" in tab.log.toPlainText())
    log = tab.log.toPlainText()
    print("\n".join(log.splitlines()[:6])); print("...")
    assert tab._last_report and Path(tab._last_report).exists(), "no report"
    print("REPORT OK:", Path(tab._last_report).name, "| lines:", len(Path(tab._last_report).read_text().splitlines()))
    if len(sys.argv) > 1:
        app.processEvents(); w.grab().save(sys.argv[1])
w.close(); print("GUI AUTO OK")
