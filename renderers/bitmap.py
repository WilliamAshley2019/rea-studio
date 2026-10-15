"""
Render a raw byte file as a 1-bit bitmap, trying several common widths.

Produces <output>_WIDTHxHEIGHT.png for each candidate size.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("PIL not installed. Run: pip install pillow")
    sys.exit(1)


def render(data: bytes, width_pixels: int, output_path: Path) -> None:
    """Render data as a 1-bit bitmap. Each bit is one pixel."""
    n_bytes = len(data)
    n_pixels = n_bytes * 8
    height = n_pixels // width_pixels
    if height == 0 or height * width_pixels > n_pixels:
        return

    img = Image.new("1", (width_pixels, height), 0)
    pixels = img.load()

    for row in range(height):
        for col in range(width_pixels):
            bit_index = row * width_pixels + col
            byte_index = bit_index // 8
            bit_in_byte = 7 - (bit_index % 8)  # MSB first
            bit = (data[byte_index] >> bit_in_byte) & 1
            pixels[col, row] = 255 if bit else 0

    img.save(output_path)
    print(f"  {output_path.name}: {width_pixels}x{height}")


def main(path: str, out_dir: str) -> None:
    data = Path(path).read_bytes()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    stem = Path(path).stem
    print(f"File: {path} ({len(data)} bytes, {len(data)*8} pixels)")

    # Candidate widths. Classic 8-pixel multiples cover text fonts and tile banks.
    # Wider widths cover screen-sized renderings.
    candidates = [
        8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
        160, 192, 224, 256, 320, 384, 448, 512, 640,
    ]

    for width in candidates:
        n_pixels = len(data) * 8
        if width > n_pixels:
            continue
        height = n_pixels // width
        if height == 0:
            continue
        # Only produce images with plausible aspect ratios
        ratio = width / height
        if ratio < 0.5 or ratio > 8.0:
            continue
        out_path = out / f"{stem}_W{width:03d}xH{height:03d}.png"
        render(data, width, out_path)

    print(f"\nWrote candidate bitmaps to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python render_bitmap.py <input.bin> <output_dir>")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])