"""Offscreen GUI smoke test: QT_QPA_PLATFORM=offscreen python tests/gui_smoke.py"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtWidgets import QApplication
import config
from bridge import AsyncBridge
from mcp_client import ReaClient
from ui.main_window import MainWindow

app = QApplication([])
cfg = config.load()
bridge = AsyncBridge()
client = ReaClient.from_config(cfg)
w = MainWindow(cfg, client, bridge); w.show(); w.connect_to_rea()

def pump(cond, secs=30):
    end = time.time() + secs
    while time.time() < end and not cond():
        app.processEvents(); time.sleep(0.02)
    assert cond(), "timeout"

pump(lambda: "Connected" in w.status.text() or "Not connected" in w.status.text())
print("STATUS:", w.status.text()); assert "Connected" in w.status.text()
tb = w.tool_browser
# select echo_tool
for i in range(tb.tree.topLevelItemCount()):
    g = tb.tree.topLevelItem(i)
    for j in range(g.childCount()):
        if g.child(j).text(0) == "echo_tool":
            tb.tree.setCurrentItem(g.child(j))
assert tb._current and tb._current.name == "echo_tool"
print("FIELDS:", [(f.name, f.kind, f.required) for f in tb.form._fields])
tb.form._fields[0].widget.setText("hi")
tb.form._fields[1].widget.setText("3")
tb.form._fields[2].widget.setPlainText('{"k": [1,2]}')
tb._call()
pump(lambda: tb.result.toPlainText().startswith("{"))
print("RESULT:", tb.result.toPlainText().replace("\n", " "))
assert '"hihihi"' in tb.result.toPlainText()
# required validation
tb.form._fields[0].widget.setText("")
tb._call(); assert "required" in tb.result.toPlainText(); print("VALIDATION OK")
# unavailable banner
tb.search.setText("search_strings")
g = tb.tree.topLevelItem(0); tb.tree.setCurrentItem(g.child(0))
tb.form._fields[0].widget.setText("flag"); tb._call()
pump(lambda: tb.banner.text() != "")
print("BANNER:", tb.banner.text())
# recipe
r = w.recipes; r.combo.setCurrentText("health_check"); r._run()
pump(lambda: r.run_btn.isEnabled() and "Recipe finished" in r.out.toPlainText())
print("RECIPE OK")
w.close()
print("ALL GOOD")
