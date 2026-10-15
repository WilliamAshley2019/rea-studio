"""Shannon entropy over 4 KiB windows, for packer / crypto detection."""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

WINDOW = 4096


@dataclass
class EntropyProfile:
    overall: float
    windows: list[float]
    high_windows: int
    max_window: float
    max_window_offset: int

    def verdict(self) -> str:
        if self.overall > 7.5 and self.windows and self.high_windows > len(self.windows) * 0.7:
            return "high entropy throughout - packed or encrypted"
        if self.high_windows:
            return f"{self.high_windows} high-entropy window(s); likely embedded compressed/encrypted blobs"
        return "entropy normal for compiled code"


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def profile(path: str, window: int = WINDOW) -> EntropyProfile:
    data = Path(path).read_bytes()
    windows = [_entropy(data[i:i + window]) for i in range(0, len(data), window)]
    overall = _entropy(data) if data else 0.0
    high = sum(1 for w in windows if w > 7.2)
    if windows:
        max_w = max(windows)
        max_off = windows.index(max_w) * window
    else:
        max_w, max_off = 0.0, 0
    return EntropyProfile(overall=overall, windows=windows,
                          high_windows=high, max_window=max_w,
                          max_window_offset=max_off)


def sparkline(profile: EntropyProfile, width: int = 64) -> str:
    if not profile.windows:
        return ""
    step = max(1, len(profile.windows) // width)
    buckets = [sum(profile.windows[i:i + step]) / len(profile.windows[i:i + step])
               for i in range(0, len(profile.windows), step)][:width]
    blocks = " .:-=+*#@"
    return "".join(blocks[min(9, int(v / 8.0 * 9))] for v in buckets)