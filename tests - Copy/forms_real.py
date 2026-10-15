"""Build a form for every real REA tool schema and round-trip its examples.
QT_QPA_PLATFORM=offscreen python tests/forms_real.py"""
import gzip, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from PySide6.QtWidgets import QApplication
from ui.forms import SchemaForm
from categories import category_of, ORDER
import collections

app = QApplication([])
tools = json.load(gzip.open(Path(__file__).with_name("real_tools.json.gz"), "rt", encoding="utf-8"))
form = SchemaForm()
kinds = collections.Counter(); bad = []; n_ex = ok_ex = 0
for t in tools:
    form.build(t["inputSchema"])
    for f in form._fields: kinds[f.kind] += 1
    for ex in form.examples:
        n_ex += 1
        form.build(t["inputSchema"])
        form.set_values(ex)
        try:
            got = form.collect()
        except Exception as e:
            bad.append((t["name"], "collect failed: %s" % e)); continue
        # every example key must come back with an equal value (defaults may add extra keys)
        diff = {k: (v, got.get(k)) for k, v in ex.items() if got.get(k) != v and v not in ('', None)}
        if diff: bad.append((t["name"], diff))
        else: ok_ex += 1
print("fields by kind:", dict(kinds))
print(f"examples round-tripped: {ok_ex}/{n_ex}")
for b in bad[:15]: print("BAD", b[0], str(b[1])[:200])
cats = collections.Counter(category_of(t["name"]) for t in tools)
for c in ORDER: print(f"  {cats[c]:3} {c}")
sys.exit(1 if bad else 0)
