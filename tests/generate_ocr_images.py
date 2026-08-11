#!/usr/bin/env python3
"""Generate deterministic PNG fixtures without Pillow/ImageMagick.

The large files use an uncompressed DEFLATE stream so their MIME payloads are
above Rspamd's 10 KiB OCR floor while retaining high-contrast OCR text.
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

FONT = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "G": ("01110", "10001", "10000", "10111", "10001", "10001", "01110"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "Q": ("01110", "10001", "10001", "10001", "10101", "10010", "01101"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "10101", "01010"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    " ": ("00000",) * 7,
}


def chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(
        ">I", zlib.crc32(kind + payload) & 0xFFFFFFFF
    )


def write_png(path: Path, text: str, width: int, height: int, scale: int, level: int) -> None:
    pixels = bytearray([255]) * (width * height * 3)
    glyph_width = 6 * scale
    text_width = max(0, len(text) * glyph_width - scale)
    start_x = max(scale, (width - text_width) // 2)
    start_y = max(scale, (height - 7 * scale) // 2)

    for index, char in enumerate(text.upper()):
        glyph = FONT[char]
        x0 = start_x + index * glyph_width
        for row, bits in enumerate(glyph):
            for col, enabled in enumerate(bits):
                if enabled != "1":
                    continue
                for dy in range(scale):
                    for dx in range(scale):
                        x = x0 + col * scale + dx
                        y = start_y + row * scale + dy
                        if 0 <= x < width and 0 <= y < height:
                            offset = (y * width + x) * 3
                            pixels[offset : offset + 3] = b"\x00\x00\x00"

    rows = bytearray()
    stride = width * 3
    for y in range(height):
        rows.append(0)
        rows.extend(pixels[y * stride : (y + 1) * stride])

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(rows), level))
    png += chunk(b"IEND", b"")
    path.write_bytes(png)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    write_png(args.output_dir / "spam.png", "BUY V1AGRA NOW", 760, 160, 8, 0)
    write_png(args.output_dir / "benign.png", "QUARTERLY NEWS", 800, 160, 8, 0)
    write_png(args.output_dir / "small-logo.png", "OK", 48, 32, 3, 9)


if __name__ == "__main__":
    main()
