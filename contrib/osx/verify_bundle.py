#!/usr/bin/env python3
"""Reject a macOS bundle containing binaries for the wrong architecture."""

import argparse
from pathlib import Path
import subprocess


def verify_bundle(bundle: Path, arch: str) -> int:
    # Mach-O (32/64 bit, either endian) and fat/universal headers.
    magics = {
        bytes.fromhex(value) for value in (
            'feedface', 'cefaedfe', 'feedfacf', 'cffaedfe',
            'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca',
        )
    }
    count = 0
    for path in sorted(bundle.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            if stream.read(4) not in magics:
                continue
        architectures = subprocess.check_output(['lipo', '-archs', str(path)], text=True).split()
        if arch not in architectures:
            raise RuntimeError(f'{path}: expected {arch}, found {architectures}')
        count += 1
    if not count:
        raise RuntimeError(f'No Mach-O binaries found in {bundle}')
    print(f'Verified {arch} support in {count} bundled Mach-O binaries.')
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', required=True, choices=('arm64', 'x86_64'))
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    verify_bundle(args.bundle, args.arch)
