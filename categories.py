"""Group REA's tools into human-sized categories (the raw names have no
consistent prefix). First matching rule wins; the last rule is the fallback."""
from __future__ import annotations

import re

RULES: list[tuple[str, str]] = [
    ("Annotations (write)", r"^(address_name|comment|inline_comment|set_|unset_|annotate_)"),
    ("Session & navigation", r"^(binary_session|open_binary|close_binary|list_documents|current_|goto_address|next_address|prev_address|get_navigation_context|inspect_address_context|list_bookmarks)"),
    ("ADB / devices", r"adb"),
    ("Frida", r"frida"),
    ("JEB", r"jeb"),
    ("Android & mobile", r"android|apktool|flutter|dart_aot|harmony"),
    ("Apple / Mach-O", r"macho|plist|swift|objc|keyed_archive|interface_builder|asset_catalog|dylib|list_architectures|apple|inspect_signature"),
    (".NET managed", r"managed"),
    ("Web & browser", r"web|browser"),
    ("JavaScript & Electron", r"javascript|electron|application|source_to_bundle"),
    ("Packets & signals", r"packet|pcap|signal"),
    ("Firmware & file formats", r"firmware|wasm|evm|sqlite|crash|go_binary|pe_resources|binary_layout|analysis_view|^(inspect|extract)_artifact"),
    ("Evidence & reconstruction", r"evidence|reconstruction|unknown|^compare_|^verify_|find_changed|correlate|capture_process"),
    ("Native analysis", r".*"),
]
_COMPILED = [(name, re.compile(rx)) for name, rx in RULES]
ORDER = [name for name, _ in RULES]


def category_of(tool_name: str) -> str:
    for name, rx in _COMPILED:
        if rx.search(tool_name):
            return name
    return "Other"
