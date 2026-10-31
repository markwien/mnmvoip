#!/usr/bin/env python3
"""Read-only root-filesystem export over pinned SSH, encrypted before disk write.

Run locally, never on the switch. Requires Python 3, ssh and GnuPG.
The caller supplies a 0600 passphrase file outside the repository.
No shell interpolation, no credentials on command lines, no unencrypted tar on disk.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

EXCLUDES = [
    './proc', './sys', './dev', './run', './tmp', './mnt', './media',
    './lost+found', './swapfile', './swap.img', './var/tmp',
    # Live SQLite files are archived consistently in a separate metadata export.
    './var/lib/freeswitch/db',
    './var/cache/apt/archives',
]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--user', default='mark')
    p.add_argument('--identity', type=Path, required=True)
    p.add_argument('--known-hosts', type=Path, required=True)
    p.add_argument('--host-key-alias', required=True)
    p.add_argument('--expected-uuid', required=True)
    p.add_argument('--passphrase-file', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--remote-command-file', type=Path)
    args = p.parse_args()
    st = args.passphrase_file.stat()
    if st.st_mode & 0o077 or st.st_uid != os.getuid():
        p.error('passphrase file must belong to caller and have mode 0600')
    if args.output.exists():
        p.error('output already exists; choose a new backup name')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    ssh = ['ssh', '-F', '/dev/null', '-i', str(args.identity),
           '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
           '-o', 'HostKeyAlias=' + args.host_key_alias,
           '-o', 'UserKnownHostsFile=' + str(args.known_hosts),
           args.user + '@' + args.host]
    actual = subprocess.check_output(ssh + ['cat /sys/hypervisor/uuid'], text=True).strip()
    if actual != args.expected_uuid:
        raise SystemExit('VM UUID does not match: refusing backup of an unexpected host')
    command = ['tar', '--one-file-system', '--acls', '--xattrs', '--numeric-owner',
               '--warning=no-file-changed', '--warning=no-file-removed', '-C', '/', '-czf', '-']
    command += ['--exclude=' + path for path in EXCLUDES]
    # EFI is a separate filesystem and is explicitly named, without following NFS.
    command += ['.', './boot/efi']
    remote = 'sudo -n ' + shlex.join(command)
    if args.remote_command_file:
        remote = args.remote_command_file.read_text()
    partial = args.output.with_name(args.output.name + '.partial')
    started = datetime.now(timezone.utc).isoformat()
    # stderr can contain paths; keep it private and report only a line count.
    with tempfile.TemporaryDirectory(prefix='voip-gpg-') as home, \
            tempfile.TemporaryFile() as errors, args.passphrase_file.open('rb') as secret:
        os.chmod(home, 0o700)
        reader = subprocess.Popen(ssh + [remote], stdout=subprocess.PIPE, stderr=errors)
        writer = subprocess.Popen(
            ['gpg', '--homedir', home, '--batch', '--yes', '--no-symkey-cache',
             '--pinentry-mode', 'loopback', '--passphrase-fd', str(secret.fileno()),
             '--cipher-algo', 'AES256', '--s2k-digest-algo', 'SHA512',
             '--s2k-count', '65011712', '--compress-algo', 'none',
             '--output', str(partial), '--symmetric'],
            stdin=reader.stdout, stdout=subprocess.DEVNULL, stderr=errors,
            pass_fds=(secret.fileno(),))
        reader.stdout.close()
        encrypt_rc = writer.wait()
        export_rc = reader.wait()
        errors.seek(0)
        diagnostics = errors.read()
    # GNU tar 1 means files changed while being read; explicitly record this.
    accepted = [0] if args.remote_command_file else [0, 1]
    if encrypt_rc != 0 or export_rc not in accepted:
        partial.unlink(missing_ok=True)
        raise SystemExit(f'backup failed: remote={export_rc}, encryption={encrypt_rc}; no usable backup published')
    partial.replace(args.output)
    report = {'started_utc': started, 'completed_utc': datetime.now(timezone.utc).isoformat(),
              'vm_uuid': actual, 'host': args.host, 'file': args.output.name,
              'bytes': args.output.stat().st_size, 'sha256': digest(args.output),
              'remote_exit_code': export_rc, 'encryption_exit_code': encrypt_rc,
              'diagnostic_lines': len(diagnostics.splitlines()),
              'live_file_copy_not_atomic_snapshot': True,
              'excludes': EXCLUDES if not args.remote_command_file else []}
    args.output.with_suffix(args.output.suffix + '.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
