"""
Render a raw byte file as a bitmap, trying several common widths and
two pixel encodings: 1 bit per pixel (packed) and 1 byte per pixel.

Produces <output>/<stem>_<mode>_W<width>xH<height>.png for each candidate.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("PIL not installed. Run: .venv\\Scripts\\python -m pip install pillow")
    sys.exit(1)


def render_1bpp(data: bytes, width: int, path: Path) -> bool:
    """Each bit is a pixel. MSB first."""
    n_pixels = len(data) * 8
    height = n_pixels // width
    if height == 0 or height > 4096:
        return False
    img = Image.new("1", (width, height), 0)
    px = img.load()
    for row in range(height):
        base = row * width
        for col in range(width):
            bit_index = base + col
            byte = data[bit_index >> 3]
            bit = (byte >> (7 - (bit_index & 7))) & 1
            px[col, row] = 255 if bit else 0
    img.save(path)
    print(f"  {path.name}: 1bpp {width}x{height}")
    return True


def render_8bpp(data: bytes, width: int, path: Path, threshold: int = 128) -> bool:
    """Each byte is a pixel; threshold to black/white."""
    height = len(data) // width
    if height == 0 or height > 4096:
        return False
    img = Image.new("1", (width, height), 0)
    px = img.load()
    for row in range(height):
        base = row * width
        for col in range(width):
            v = data[base + col]
            px[col, row] = 255 if v >= threshold else 0
    img.save(path)
    print(f"  {path.name}: 8bpp {width}x{height}")
    return True


def main(path: str, out_dir: str) -> None:
    data = Path(path).read_bytes()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(path).stem

    print(f"File: {path} ({len(data)} bytes)")

    # Candidate widths for both modes.
    # 8bpp only makes sense for widths <= file size; large widths are screen dumps.
    width_candidates = [
        8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 100, 120, 128, 160, 192,
        200, 240, 256, 320, 384, 448, 512, 640, 720, 800,
    ]

    print(f"\nRendering 1 bit per pixel (packed):")
    for w in width_candidates:
        render_1bpp(data, w, out / f"{stem}_1bpp_W{w:04d}.png")

    print(f"\nRendering 8 bits per pixel (one byte = one pixel):")
    for w in width_candidates:
        if w > len(data):
            continue
        render_8bpp(data, w, out / f"{stem}_8bpp_W{w:04d}.png")

    print(f"\nWrote candidate bitmaps to {out}")
    print("Open the images and look for recognizable patterns:")
    print("  - Sprites/glyphs: 1bpp at W=8, 16, 24, 32")
    print("  - Text font: 8bpp at W=8 or 16 (chars side by side)")
    print("  - Screen layouts: 1bpp or 8bpp at W=640 or 320")
    print("  - Woven/wafer look: wrong width, try neighboring values")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python render_bitmap.py <input.bin> <output_dir>")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])