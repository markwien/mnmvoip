#!/usr/bin/env python3
"""Execute through root SSH; writes only a compressed recovery tar to stdout.

Read-only inventories and SQLite online-backup copies are gathered in RAM.
No services/configuration are changed. The receiver must encrypt stdout.
"""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time


def main():
    os.umask(0o077)
    entries = {}
    commands = {
        'packages.tsv': ['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'],
        'apt-manual.txt': ['apt-mark', 'showmanual'],
        'network.json': ['ip', '-j', 'address'],
        'routes.json': ['ip', '-j', 'route'],
        'firewall.nft': ['nft', 'list', 'ruleset'],
        'firewall.json': ['nft', '-j', 'list', 'ruleset'],
        'mounts.json': ['findmnt', '-J', '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS'],
        'disks.json': ['lsblk', '-J', '-o', 'NAME,SIZE,FSTYPE,UUID,PARTUUID,MOUNTPOINTS'],
        'partition-table.txt': ['sfdisk', '--dump', '/dev/xvda'],
        'block-identifiers.txt': ['blkid'],
        'units.txt': ['systemctl', 'list-unit-files', '--no-pager'],
        'timers.txt': ['systemctl', 'list-timers', '--all', '--no-pager'],
        'freeswitch-unit.txt': ['systemctl', 'cat', 'freeswitch'],
        'freeswitch-version.txt': ['/usr/local/bin/fs_cli', '-x', 'version'],
        'freeswitch-status.txt': ['/usr/local/bin/fs_cli', '-x', 'status'],
        'freeswitch-libraries.txt': ['ldd', '/opt/freeswitch/bin/freeswitch'],
        'freeswitch-modules.txt': ['/usr/local/bin/fs_cli', '-x', 'show modules'],
        'kernel.txt': ['uname', '-a'],
    }
    statuses = {}
    for name, command in commands.items():
        try:
            result = subprocess.run(command, capture_output=True, timeout=45)
            entries[name] = result.stdout
            statuses[name] = {'exit_code': result.returncode, 'stderr_present': bool(result.stderr)}
        except (OSError, subprocess.TimeoutExpired) as error:
            statuses[name] = {'error': type(error).__name__}
    hashes = {}
    for root in ['/etc', '/usr/local', '/opt/freeswitch', '/var/lib/freeswitch/scripts']:
        for path in Path(root).rglob('*'):
            if path.is_file() and not path.is_symlink():
                try:
                    hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    pass
    entries['critical-file-sha256.json'] = json.dumps(hashes, indent=2).encode()
    db_status = {}
    with tempfile.TemporaryDirectory(prefix='voip-recovery-', dir='/dev/shm') as temp:
        for path in sorted(Path('/var/lib/freeswitch/db').glob('*.db')):
            try:
                dest = Path(temp) / path.name
                deadline = time.monotonic() + 20

                def progress(status, remaining, total):
                    if time.monotonic() > deadline:
                        raise TimeoutError('SQLite backup exceeded deadline')

                with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2) as source, sqlite3.connect(dest) as target:
                    source.backup(target, pages=128, progress=progress, sleep=0.05)
                    integrity = target.execute('PRAGMA integrity_check').fetchall()
                    if integrity != [('ok',)]:
                        raise RuntimeError('SQLite integrity check failed')
                entries['sqlite/' + path.name] = dest.read_bytes()
                db_status[path.name] = 'online backup; integrity_check=ok'
            except Exception as error:
                db_status[path.name] = 'FAILED:' + type(error).__name__
    info = {'created_utc': datetime.now(timezone.utc).isoformat(),
            'vm_uuid': Path('/sys/hypervisor/uuid').read_text().strip(),
            'hostname': Path('/etc/hostname').read_text().strip(),
            'commands': statuses, 'sqlite': db_status,
            'external_ccsystem_database_included': False,
            'sqlite_snapshots_are_individual_not_cross_database_transactions': True}
    entries['metadata.json'] = json.dumps(info, indent=2).encode()
    if any(value.startswith('FAILED') for value in db_status.values()):
        raise SystemExit('SQLite backup failed; refuse incomplete metadata export')
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o600
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


if __name__ == '__main__':
    main()
