#!/usr/bin/env python3
"""Authenticate/decrypt backups, read every tar member and compare code/config hashes.

No archive is extracted to a live filesystem; only metadata stays in memory.
Run on the two reassembled GPG files using the separately stored key file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import subprocess
import tarfile
import tempfile


def read_archive(path, key, callback):
    with tempfile.TemporaryDirectory(prefix='voip-verify-') as home, key.open('rb') as secret:
        os.chmod(home, 0o700)
        proc = subprocess.Popen(
            ['gpg', '--homedir', home, '--batch', '--no-symkey-cache',
             '--pinentry-mode', 'loopback', '--passphrase-fd', str(secret.fileno()),
             '--decrypt', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(secret.fileno(),))
        try:
            with tarfile.open(fileobj=proc.stdout, mode='r|gz') as archive:
                for item in archive:
                    parts = PurePosixPath(item.name).parts
                    if item.name.startswith('/') or '..' in parts:
                        raise ValueError('unexpected unsafe archive member')
                    callback(item, archive.extractfile(item) if item.isfile() else None)
            # Consume remaining OpenPGP packets so the integrity/MDC result is checked.
            while proc.stdout.read(1024 * 1024):
                pass
        except BaseException:
            proc.kill()
            proc.communicate()
            raise
        _, _ = proc.communicate()
        if proc.returncode:
            raise ValueError('GPG decryption/authentication failed')


def verify(rootfs, metadata, key):
    data = {}

    def collect(item, stream):
        if stream:
            data[item.name] = stream.read()

    read_archive(metadata, key, collect)
    expected = json.loads(data['critical-file-sha256.json'])
    info = json.loads(data['metadata.json'])
    dbs = 0
    with tempfile.TemporaryDirectory(prefix='voip-sqlite-check-') as temp:
        os.chmod(temp, 0o700)
        for name, value in data.items():
            if name.startswith('sqlite/'):
                path = Path(temp) / Path(name).name
                path.write_bytes(value)
                path.chmod(0o600)
                with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
                    if conn.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        raise ValueError('restored SQLite snapshot failed integrity check')
                dbs += 1
    if not dbs:
        raise ValueError('no consistent SQLite snapshots present')
    seen = set()
    mismatches = []
    checked = []
    counts = {'members': 0, 'regular_files': 0, 'uncompressed_bytes': 0}
    stable_prefixes = ['/opt/freeswitch/', '/usr/local/', '/var/lib/freeswitch/scripts/',
                       '/etc/systemd/system/', '/etc/network/', '/etc/voip38/', '/etc/voip50/']

    def check(item, stream):
        name = '/' + item.name.removeprefix('./').lstrip('/')
        seen.add(name)
        counts['members'] += 1
        if stream:
            counts['regular_files'] += 1
            hasher = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(block)
                counts['uncompressed_bytes'] += len(block)
            if name in expected and any(name.startswith(prefix) for prefix in stable_prefixes):
                checked.append(name)
                if hasher.hexdigest() != expected[name]:
                    mismatches.append(name)

    read_archive(rootfs, key, check)
    required = ['/opt/freeswitch/bin/freeswitch', '/etc/freeswitch/freeswitch.xml',
                '/etc/passwd', '/etc/shadow', '/etc/odbc.ini', '/etc/nftables.conf',
                '/etc/network/interfaces', '/var/lib/dpkg/status',
                '/var/lib/freeswitch/scripts/dbconnect.lua', '/boot/efi/EFI']
    missing = [name for name in required if name not in seen]
    absent_hash_files = [name for name in expected
                         if any(name.startswith(prefix) for prefix in stable_prefixes) and name not in seen]
    if missing or mismatches or absent_hash_files:
        raise ValueError(json.dumps({'missing_required': missing, 'hash_mismatch': mismatches,
                                     'missing_hashed_files': absent_hash_files}))
    return {'verified': True, 'vm_uuid': info['vm_uuid'], 'hostname': info['hostname'],
            'gpg_integrity_verified': True, 'all_tar_file_contents_read': True,
            'stable_code_and_config_hashes_matched': len(checked),
            'consistent_sqlite_snapshots_integrity_ok': dbs, **counts,
            'external_ccsystem_database_included': False,
            'boot_restore_test_performed': False,
            'live_file_copy_not_atomic_disk_image': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rootfs', type=Path, required=True)
    p.add_argument('--metadata', type=Path, required=True)
    p.add_argument('--passphrase-file', type=Path, required=True)
    p.add_argument('--report', type=Path)
    args = p.parse_args()
    result = verify(args.rootfs, args.metadata, args.passphrase_file)
    text = json.dumps(result, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
