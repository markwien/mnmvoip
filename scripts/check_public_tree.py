#!/usr/bin/env python3
"""Check plaintext publication rules and authenticated encrypted-part manifests.

This is a guard against obvious mistakes, not a substitute for manual review or
comparison against the real secret values before publication.
"""
import hashlib
import json
from pathlib import Path
import re


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = root / 'backups/2026-10-31/manifest.json'
    data = json.loads(manifest.read_text())
    allowed = {}
    for artifact in data['artifacts']:
        complete = hashlib.sha256()
        total = 0
        for part in artifact['parts']:
            name = manifest.parent / part['file']
            raw = name.read_bytes()
            if len(raw) != part['bytes'] or hashlib.sha256(raw).hexdigest() != part['sha256']:
                raise SystemExit('encrypted part checksum failed: ' + part['file'])
            allowed[name] = True
            complete.update(raw)
            total += len(raw)
        if total != artifact['bytes'] or complete.hexdigest() != artifact['sha256']:
            raise SystemExit('complete archive checksum failed')
    errors = []
    checked = 0
    for path in root.rglob('*'):
        if not path.is_file() or any(part in ['.git', '__pycache__', 'restore-work'] for part in path.parts):
            continue
        if path in allowed:
            continue
        name = str(path.relative_to(root))
        if path.name in ['recovery-passphrase.txt', '.fs_cli_conf', 'odbc.ini', 'shadow', 'id_rsa', 'id_ed25519']:
            errors.append(name + ': private filename')
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            errors.append(name + ': unexpected binary outside encrypted allowlist')
            continue
        for pattern in [r'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',
                        r'(?m)^\w+:\$(?:6|y)\$[^\n:]+:',
                        r'(?i)https?://[^\s/]+:[^\s/@]+@',
                        r'(?i)github_pat_[A-Za-z0-9_]{20,}', r'gh[pousr]_[A-Za-z0-9]{20,}']:
            if re.search(pattern, text):
                errors.append(name + ': forbidden plaintext pattern')
        checked += 1
    if errors:
        raise SystemExit('\n'.join(errors))
    print(json.dumps({'plaintext_files_checked': checked, 'encrypted_parts_checked': len(allowed),
                      'encrypted_bytes': sum(a['bytes'] for a in data['artifacts']),
                      'obvious_plaintext_secret_patterns': 0}))


if __name__ == '__main__':
    main()
