#!/usr/bin/env python3
"""Verify encrypted chunks and reassemble exact files from a public manifest."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def reassemble(manifest, output):
    data = json.loads(manifest.read_text())
    output.mkdir(parents=True, exist_ok=True)
    for artifact in data['artifacts']:
        target = output / artifact['file']
        if target.name != artifact['file']:
            raise ValueError('unsafe output filename')
        # Preflight all parts before writing anything for this artifact.
        parts = []
        for part in artifact['parts']:
            name = Path(part['file'])
            if name.is_absolute() or '..' in name.parts:
                raise ValueError('unsafe part filename')
            path = manifest.parent / name
            if path.stat().st_size != part['bytes'] or sha(path) != part['sha256']:
                raise ValueError('encrypted chunk failed checksum: ' + str(name))
            parts.append(path)
        if target.exists():
            if target.stat().st_size == artifact['bytes'] and sha(target) == artifact['sha256']:
                print(target.name + ': already verified')
                continue
            raise ValueError('refusing to overwrite existing different output')
        partial = target.with_name(target.name + '.partial')
        try:
            with partial.open('xb') as dst:
                for path in parts:
                    with path.open('rb') as src:
                        for block in iter(lambda: src.read(1024 * 1024), b''):
                            dst.write(block)
            if partial.stat().st_size != artifact['bytes'] or sha(partial) != artifact['sha256']:
                raise ValueError('reassembled backup failed checksum')
            partial.replace(target)
        finally:
            partial.unlink(missing_ok=True)
        print(target.name + ': verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    reassemble(a.manifest, a.output)
