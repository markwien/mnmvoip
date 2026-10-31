#!/usr/bin/python3
"""Read-only NAS announcement mirror, with validated local generations."""
import ctypes
import ctypes.util
import datetime
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

SOURCE = Path('/mnt/voip50-prompts')
SOURCE_SPEC = '192.168.1.214:/volume1/freeswitchSounds/en/us/callie/mark'
DEST = Path('/var/lib/freeswitch/sounds/en/us/callie/mark')
GENERATIONS = Path('/var/lib/freeswitch/prompt-generations')
STATUS = Path('/root/voip50-build/prompt-sync-status.json')
PATTERN = re.compile(r'promptFile_[0-9]+\.wav\Z')


class SoundInfo(ctypes.Structure):
    _fields_ = [('frames', ctypes.c_int64), ('samplerate', ctypes.c_int),
                ('channels', ctypes.c_int), ('format', ctypes.c_int),
                ('sections', ctypes.c_int), ('seekable', ctypes.c_int)]


def write_status(value):
    value['checked_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    temp = STATUS.with_name(STATUS.name + '.new')
    temp.write_text(json.dumps(value, indent=2))
    temp.chmod(0o600)
    temp.replace(STATUS)


def main():
    os.umask(0o077)
    gid = grp.getgrnam('freeswitch').gr_gid
    GENERATIONS.mkdir(parents=True, exist_ok=True)
    GENERATIONS.chmod(0o750)
    os.chown(GENERATIONS, 0, gid)
    lock = (GENERATIONS / 'sync.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    # Listing triggers the configured read-only automount; an empty mountpoint is never a valid source.
    files = sorted(SOURCE.iterdir())
    result = subprocess.run(['findmnt', '-J', '-M', str(SOURCE), '-t', 'nfs,nfs4',
                             '-o', 'SOURCE,FSTYPE,OPTIONS'],
                            check=True, capture_output=True, text=True)
    mounts = json.loads(result.stdout)['filesystems']
    if len(mounts) != 1:
        raise ValueError('expected exactly one NFS announcement mount')
    mount = mounts[0]
    if mount['source'] != SOURCE_SPEC or mount['fstype'] not in ['nfs', 'nfs4'] or 'ro' not in mount['options'].split(','):
        raise ValueError('expected read-only NAS mount is unavailable')
    expected = set()
    operating_mode = Path('/etc/voip50/mode').read_text().strip()
    if operating_mode not in ['BUILD', 'LIVE']:
        raise ValueError('invalid operating mode')
    cache_name = 'voip50-live-xml-cache' if operating_mode == 'LIVE' else 'voip50-xml-cache'
    cache = Path('/var/lib/freeswitch') / cache_name / 'current/ivrXML'
    text = re.sub(r'<\?xml[^>]*\?>', '', cache.read_text())
    for node in ET.fromstring('<reference>' + text + '</reference>').iter():
        for key, value in node.attrib.items():
            if value.startswith('mark/') and PATTERN.fullmatch(Path(value).name):
                expected.add(Path(value).name)
    selected = [f for f in files if PATTERN.fullmatch(f.name)]
    if not selected or len(selected) > 10000 or not expected.issubset({f.name for f in selected}):
        raise ValueError('source is empty or missing currently configured announcements')
    generation = GENERATIONS / ('generation-' + uuid.uuid4().hex)
    generation.mkdir(mode=0o750)
    generation.chmod(0o750)
    os.chown(generation, 0, gid)
    library = ctypes.CDLL(ctypes.util.find_library('sndfile'))
    library.sf_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(SoundInfo)]
    library.sf_open.restype = ctypes.c_void_p
    library.sf_close.argtypes = [ctypes.c_void_p]
    total = 0
    manifest = {}
    try:
        for source in selected:
            before = source.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size < 44 or before.st_size > 64 * 1024 * 1024:
                raise ValueError('invalid announcement file type or size')
            total += before.st_size
            if total > 1024 * 1024 * 1024:
                raise ValueError('announcement mirror exceeds size limit')
            target = generation / source.name
            digest = hashlib.sha256()
            with source.open('rb') as src, target.open('wb') as dst:
                while True:
                    data = src.read(1024 * 1024)
                    if not data:
                        break
                    digest.update(data)
                    dst.write(data)
            after = source.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or target.stat().st_size != before.st_size:
                raise ValueError('announcement changed while copying')
            with target.open('rb') as file:
                header = file.read(12)
            if header[:4] not in [b'RIFF', b'RIFX', b'RF64'] or header[8:12] != b'WAVE':
                raise ValueError('not a WAV announcement')
            info = SoundInfo()
            handle = library.sf_open(os.fsencode(target), 0x10, ctypes.byref(info))
            if not handle:
                raise ValueError('announcement cannot be decoded by the installed sound library')
            library.sf_close(handle)
            if info.frames <= 0 or not 1 <= info.channels <= 8 or not 8000 <= info.samplerate <= 192000:
                raise ValueError('invalid decoded announcement metadata')
            target.chmod(0o640)
            os.chown(target, 0, gid)
            manifest[source.name] = digest.hexdigest()
        if DEST.is_symlink():
            previous = DEST.resolve()
            if previous.parent != GENERATIONS:
                raise ValueError('unexpected announcement destination')
        else:
            if not DEST.is_dir():
                raise ValueError('initial announcement directory missing')
            previous = GENERATIONS / ('initial-' + uuid.uuid4().hex)
            DEST.rename(previous)
        temporary = DEST.with_name(DEST.name + '.new')
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(generation)
        try:
            temporary.replace(DEST)
        except Exception:
            if not DEST.exists() and previous.exists():
                previous.rename(DEST)
            raise
        for old in list(GENERATIONS.glob('generation-*')) + list(GENERATIONS.glob('initial-*')):
            if old not in [generation, previous]:
                shutil.rmtree(old)
        write_status({'success': True, 'source': SOURCE_SPEC, 'source_read_only': True,
                      'files': len(selected), 'bytes': total, 'required_files': len(expected),
                      'all_required_present': True, 'generation': generation.name,
                      'previous_generation_retained': True, 'destination': str(DEST),
                      'scope': 'promptFile_*.wav only; no conversation recordings'})
    except Exception:
        if generation.exists() and (not DEST.is_symlink() or DEST.resolve() != generation):
            shutil.rmtree(generation)
        raise


if __name__ == '__main__':
    try:
        main()
        print('Validated announcement generation synchronized')
    except Exception as error:
        write_status({'success': False, 'existing_files_retained': True, 'error_type': type(error).__name__})
        print('Announcement synchronization failed; existing files retained', file=sys.stderr)
        raise SystemExit(1)
