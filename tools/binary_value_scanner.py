from __future__ import annotations

import argparse
import math
import re
import struct
from pathlib import Path


PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def encodings(value: float) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if float(value).is_integer():
        integer = int(value)
        if -(2**31) <= integer < 2**31:
            out += [
                ("int32-le", struct.pack("<i", integer)),
                ("int32-be", struct.pack(">i", integer)),
            ]
        text = str(integer)
    else:
        text = format(value, "g")
    out += [
        ("float32-le", struct.pack("<f", float(value))),
        ("float32-be", struct.pack(">f", float(value))),
        ("float64-le", struct.pack("<d", float(value))),
        ("float64-be", struct.pack(">d", float(value))),
        ("ascii", text.encode("ascii")),
        ("utf16-le", text.encode("utf-16-le")),
        ("utf16-be", text.encode("utf-16-be")),
    ]
    # Some representations can be byte-identical for special values.
    unique = []
    seen = set()
    for name, needle in out:
        key = (name, needle)
        if key not in seen:
            seen.add(key)
            unique.append((name, needle))
    return unique


def ascii_strings(data: bytes, absolute_start: int) -> list[str]:
    found = []
    for match in PRINTABLE_RE.finditer(data):
        found.append(f"0x{absolute_start + match.start():X}: {match.group().decode('ascii', errors='replace')}")
    return found


def hex_dump(data: bytes, absolute_start: int, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  {absolute_start + i:08X}  {hx:<{width * 3 - 1}}  {txt}")
    return "\n".join(lines)


def scan_file(path: Path, value: float, context: int, max_hits: int | None) -> int:
    raw = path.read_bytes()
    hits = []
    seen = set()
    for kind, needle in encodings(value):
        start = 0
        while True:
            pos = raw.find(needle, start)
            if pos < 0:
                break
            key = (pos, kind)
            if key not in seen:
                seen.add(key)
                hits.append((pos, kind, needle))
            start = pos + 1

    hits.sort(key=lambda item: (item[0], item[1]))
    if max_hits is not None:
        hits = hits[:max_hits]

    if not hits:
        return 0

    print(f"\n=== {path} ===")
    print(f"size={len(raw):,} bytes | value={value:g} | hits={len(hits)}")
    for index, (pos, kind, needle) in enumerate(hits, 1):
        lo = max(0, pos - context)
        hi = min(len(raw), pos + len(needle) + context)
        block = raw[lo:hi]
        print(f"\n[{index}] offset=0x{pos:X} ({pos}) type={kind} bytes={needle.hex(' ')}")
        print(hex_dump(block, lo))
        strings = ascii_strings(block, lo)
        if strings:
            print("  nearby ASCII:")
            for s in strings:
                print("   ", s)
    return len(hits)


def iter_files(targets: list[Path], recursive: bool) -> list[Path]:
    files = []
    for target in targets:
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            iterator = target.rglob("*") if recursive else target.glob("*")
            files.extend(p for p in iterator if p.is_file())
        else:
            print(f"WARNING: not found: {target}")
    return sorted(set(files))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search binary files for a numeric value in common binary/text representations."
    )
    parser.add_argument("targets", nargs="+", type=Path, help="Files or directories to scan")
    parser.add_argument("--value", "-v", type=float, required=True, help="Value to search for, e.g. 50000")
    parser.add_argument("--context", "-c", type=int, default=64, help="Bytes shown before/after a hit (default: 64)")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    parser.add_argument("--max-hits", type=int, default=None, help="Maximum hits displayed per file")
    args = parser.parse_args()

    if not math.isfinite(args.value):
        parser.error("--value must be finite")
    if args.context < 0:
        parser.error("--context must be >= 0")

    files = iter_files(args.targets, args.recursive)
    if not files:
        parser.error("No files to scan")

    total = 0
    matched_files = 0
    for path in files:
        try:
            count = scan_file(path, args.value, args.context, args.max_hits)
        except OSError as exc:
            print(f"ERROR: {path}: {exc}")
            continue
        if count:
            matched_files += 1
            total += count

    print(f"\nDone. Scanned {len(files)} file(s); {matched_files} matched; {total} hit(s).")


if __name__ == "__main__":
    main()
