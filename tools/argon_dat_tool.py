from pathlib import Path
import argparse


def crypt(data: bytes, key: int = 0) -> bytes:
    return bytes(b ^ ((i - 0x35 + key) & 0xFF) for i, b in enumerate(data))


def parse_dat(path: Path):
    raw = path.read_bytes()
    pos = 0
    entries = []
    while pos < len(raw):
        start = pos
        name_len = crypt(raw[pos:pos+1])[0]
        pos += 1
        if not name_len:
            break
        name = crypt(raw[pos:pos+name_len]).decode('utf-8')
        pos += name_len
        flag = crypt(raw[pos:pos+1])[0]
        pos += 1
        size = int.from_bytes(crypt(raw[pos:pos+4]), 'little')
        pos += 4
        if pos + size > len(raw):
            raise ValueError(f'Invalid entry at 0x{start:X}: {name}, size={size}')
        payload = crypt(raw[pos:pos+size])
        pos += size
        entries.append((name, flag, payload))
    if pos != len(raw):
        raise ValueError(f'Archive not fully consumed: {pos}/{len(raw)} bytes')
    return entries


def extract(path: Path, out_dir: Path):
    entries = parse_dat(path)
    manifest = []
    for index, (name, flag, payload) in enumerate(entries):
        dest = out_dir / Path(name.replace('\\', '/'))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        manifest.append(f'{index}\t{flag}\t{name}')
    (out_dir / '_argon_manifest.tsv').write_text('\n'.join(manifest), encoding='utf-8')
    print(f'Extracted {len(entries)} files to {out_dir}')


def repack(src_dir: Path, out_path: Path):
    manifest_path = src_dir / '_argon_manifest.tsv'
    if not manifest_path.exists():
        raise FileNotFoundError('Missing _argon_manifest.tsv; extract the DAT with this tool first.')
    out = bytearray()
    count = 0
    for line in manifest_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        _, flag_s, name = line.split('\t', 2)
        flag = int(flag_s)
        payload = (src_dir / Path(name.replace('\\', '/'))).read_bytes()
        name_b = name.encode('utf-8')
        if len(name_b) > 255:
            raise ValueError(f'Filename too long: {name}')
        out += crypt(bytes([len(name_b)]))
        out += crypt(name_b)
        out += crypt(bytes([flag]))
        out += crypt(len(payload).to_bytes(4, 'little'))
        out += crypt(payload)
        count += 1
    out_path.write_bytes(out)
    print(f'Repacked {count} files to {out_path} ({len(out)} bytes)')


def main():
    ap = argparse.ArgumentParser(description="Argon 5 DAT extractor/repacker for Farmer's Dynasty GameData.dat")
    sub = ap.add_subparsers(dest='cmd', required=True)
    ex = sub.add_parser('extract'); ex.add_argument('dat', type=Path); ex.add_argument('out', type=Path)
    rp = sub.add_parser('repack'); rp.add_argument('folder', type=Path); rp.add_argument('out', type=Path)
    args = ap.parse_args()
    if args.cmd == 'extract': extract(args.dat, args.out)
    else: repack(args.folder, args.out)

if __name__ == '__main__': main()
