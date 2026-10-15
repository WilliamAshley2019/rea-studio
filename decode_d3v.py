"""
Decode an FCExporter database.d3v archive into JSON.

Actual on-disk format:
  Header:
    uint32  magic        (big-endian; value 0xD3010401)
    uint16  item_count   (big-endian)
  Per entry:
    uint32  name_length  (big-endian)
    bytes   name         (UTF-8)
    uint8   compressed   (0 = raw, 1 = gzip)
    uint32  element_size (big-endian)
    uint32  payload_len  (big-endian)
    bytes   payload      (raw or gzip)
"""
from __future__ import annotations

import gzip
import json
import struct
import sys
from pathlib import Path


def decode(path: str) -> dict:
    data = Path(path).read_bytes()
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic != 0xD3010401:
        return {"error": f"Bad magic: 0x{magic:08X}"}
    count = struct.unpack_from(">H", data, 4)[0]  # uint16, not uint32
    off = 6  # entries start here, not 8

    entries = []
    for i in range(count):
        if off >= len(data):
            break
        try:
            name_len = struct.unpack_from(">I", data, off)[0]; off += 4
            name = data[off:off + name_len].decode("utf-8", errors="replace"); off += name_len
            compressed = data[off]; off += 1
            elem_size = struct.unpack_from(">I", data, off)[0]; off += 4
            payload_len = struct.unpack_from(">I", data, off)[0]; off += 4
            payload = data[off:off + payload_len]; off += payload_len

            if compressed:
                payload = gzip.decompress(payload)

            # Summarize without dumping the whole table
            n_elems = len(payload) // elem_size if elem_size else 0
            words = []
            if elem_size == 4:
                for j in range(min(6, len(payload) // 4)):
                    words.append(f"0x{struct.unpack_from('<I', payload, j*4)[0]:08X}")
            elif elem_size == 8:
                for j in range(min(4, len(payload) // 8)):
                    words.append(f"0x{struct.unpack_from('<Q', payload, j*8)[0]:016X}")
            elif elem_size == 1:
                words = [f"0x{b:02X}" for b in payload[:8]]

            entries.append({
                "index": i,
                "name": name,
                "compressed": bool(compressed),
                "byte_length": len(payload),
                "element_size": elem_size,
                "element_count": n_elems,
                "sample": words,
            })
        except Exception as e:
            entries.append({"index": i, "error": str(e)})
            break

    return {
        "path": str(path),
        "magic": f"0x{magic:08X}",
        "item_count": count,
        "decoded": len(entries),
        "entries": entries,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decode_d3v.py <input.d3v> <output.json>")
        sys.exit(2)
    result = decode(sys.argv[1])
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {sys.argv[2]}")
    print(f"Declared items: {result.get('item_count', 0)}")
    print(f"Decoded entries: {result.get('decoded', 0)}")