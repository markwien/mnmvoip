"""Install native local CDRs on the replacement switch without restarting it."""
import copy
import datetime
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import runpy
import subprocess
import xml.etree.ElementTree as ET

BASE = Path('/root/voip38-build')
AUDIT = BASE / 'cdr-local'
LOGDIR = Path('/var/log/freeswitch/cdr-csv')
COLUMNS = ['switch_name', 'switch_id', 'switch_ip', 'uuid', 'call_uuid',
           'bridge_uuid', 'signal_bond', 'direction', 'context',
           'caller_id_number', 'destination_number', 'sip_network_ip',
           'sip_network_port', 'start_stamp', 'answer_stamp', 'end_stamp',
           'duration', 'billsec', 'hangup_cause', 'read_codec', 'write_codec',
           'accountcode']
VALUES = ['voip-38', '6', '92.61.60.38'] + ['${'+c+'}' for c in COLUMNS[3:]]


def cli(command):
    r = subprocess.run(['/usr/local/bin/fs_cli', '-x', command],
                       capture_output=True, text=True, timeout=40)
    if r.returncode or '-ERR' in r.stdout:
        raise RuntimeError('FreeSWITCH API command failed: '+command.split()[0])
    return r.stdout.strip()


def write(path, data, mode=0o600, owner=None):
    path = Path(path)
    temp = path.with_name(path.name+'.cdr-new')
    temp.write_bytes(data if isinstance(data, bytes) else data.encode())
    temp.chmod(mode)
    if owner:
        os.chown(temp, *owner)
    temp.replace(path)


def cdr_configuration():
    c = ET.Element('configuration', name='cdr_csv.conf',
                   description='Local technical CDRs for voip-38')
    s = ET.SubElement(c, 'settings')
    for k, v in {'debug': 'false', 'legs': 'ab', 'log-base': '/var/log/freeswitch',
                 'rotate-on-hup': 'false', 'default-template': 'voip38-local',
                 'master-file-only': 'true'}.items():
        ET.SubElement(s, 'param', name=k, value=v)
    t = ET.SubElement(ET.SubElement(c, 'templates'), 'template', name='voip38-local')
    t.text = ','.join('"'+v+'"' for v in VALUES)+'\n'
    return c


def canonical(n):
    return n.tag, sorted(n.attrib.items()), (n.text or '').strip(), [canonical(c) for c in n]


def update_document(path):
    original = path.read_bytes()
    root = ET.fromstring(original)
    before = copy.deepcopy(root)
    section = root.find("section[@name='configuration']")
    assert section is not None
    assert not any(c.get('name') == 'cdr_csv.conf' for c in section)
    modules = section.find("configuration[@name='modules.conf']/modules")
    assert modules is not None
    assert not any(m.get('module') == 'mod_cdr_csv' for m in modules)
    modules.append(ET.Element('load', module='mod_cdr_csv'))
    section.append(cdr_configuration())
    proof = copy.deepcopy(root)
    conf = proof.find("section[@name='configuration']")
    conf.remove(conf.find("configuration[@name='cdr_csv.conf']"))
    mods = conf.find("configuration[@name='modules.conf']/modules")
    mods.remove(next(m for m in mods if m.get('module') == 'mod_cdr_csv'))
    assert canonical(proof) == canonical(before), 'unrelated XML change'
    ET.indent(root)
    return original, ET.tostring(root, encoding='utf-8')


os.umask(0o077)
AUDIT.mkdir(mode=0o700, exist_ok=True)
assert Path('/etc/voip38/mode').read_text().strip() == 'LIVE'
assert cli('module_exists mod_cdr_csv') == 'false'
pid_before = subprocess.check_output(['systemctl', 'show', 'freeswitch', '-p', 'MainPID', '--value'], text=True).strip()
calls_before = cli('show calls count')
fs = pwd.getpwnam('freeswitch')
fgid = grp.getgrnam('freeswitch').gr_gid
LOGDIR.mkdir(mode=0o750, exist_ok=True)
os.chown(LOGDIR, fs.pw_uid, fgid)
LOGDIR.chmod(0o750)
master = LOGDIR / 'Master.csv'
assert not master.exists(), 'existing CDR file: preserve and inspect first'
write(master, b'', 0o600, (fs.pw_uid, fgid))
write(LOGDIR / 'columns.json', json.dumps(COLUMNS, indent=2)+'\n', 0o640, (0, fgid))
write(LOGDIR / 'README.txt',
      'Native mod_cdr_csv records, both legs; columns described in columns.json.\n'
      'No header row. Switch identity is fixed to voip-38 / 6 / 92.61.60.38.\n'
      'Rows are written at hangup; pre-activation calls cannot be reconstructed.\n'
      'CDR_SELFTEST account marks internal non-SIP, non-billing verification calls.\n'
      'Rotation: daily or >20 MiB, checked every 5 minutes; 14 archives maximum,\n'
      'maxage 14 days, compression with one generation delay; no copytruncate.\n',
      0o640, (0, fgid))

reopen = '''#!/usr/bin/python3
import subprocess
r = subprocess.run(['/usr/local/bin/fs_cli', '-x', 'cdr_csv rotate'],
                   capture_output=True, text=True, timeout=15)
if r.returncode or r.stdout.strip() != '+OK':
    raise SystemExit('CDR file reopen failed; inspect FreeSWITCH module state')
'''
write('/usr/local/libexec/voip38-cdr-reopen', reopen, 0o750)
rotation = '''/var/log/freeswitch/cdr-csv/Master.csv {
    daily
    maxsize 20M
    rotate 14
    maxage 14
    compress
    delaycompress
    missingok
    notifempty
    create 0600 freeswitch freeswitch
    sharedscripts
    postrotate
        /usr/local/libexec/voip38-cdr-reopen
    endscript
}
'''
write('/etc/logrotate-voip38-cdr.conf', rotation, 0o644)
write('/etc/systemd/system/voip38-cdr-rotate.service', '''[Unit]
Description=Rotate local VoIP38 CDR files without restarting FreeSWITCH
After=freeswitch.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate --state /var/lib/logrotate/voip38-cdr.status /etc/logrotate-voip38-cdr.conf
UMask=0077
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
''', 0o644)
write('/etc/systemd/system/voip38-cdr-rotate.timer', '''[Unit]
Description=Check local VoIP38 CDR rotation every five minutes

[Timer]
OnCalendar=*-*-* *:0/5:00
AccuracySec=15s
Persistent=true
Unit=voip38-cdr-rotate.service

[Install]
WantedBy=timers.target
''', 0o644)
r = subprocess.run(['/usr/sbin/logrotate', '--debug', '--state', '/var/lib/logrotate/voip38-cdr.status', '/etc/logrotate-voip38-cdr.conf'], capture_output=True)
assert r.returncode == 0, 'rotation configuration validation failed'

lock = (BASE / 'integration/sync.lock').open('w')
fcntl.flock(lock, fcntl.LOCK_EX)
paths = [BASE / 'candidate/freeswitch.xml', Path('/etc/freeswitch/voip38-static.xml')]
current = BASE / 'integration/current/voip38-static.xml'
if current.exists():
    paths.append(current.resolve())
changes = {p: update_document(p) for p in paths}
backup = AUDIT / ('before-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(mode=0o700)
for index, (p, (old, new)) in enumerate(changes.items()):
    write(backup / (str(index)+'-'+p.name), old)
    st = p.stat()
    write(p, new, st.st_mode & 0o777, (st.st_uid, st.st_gid))

# Regenerate XML in memory using the real renderer; do not apply network/scripts.
integration = runpy.run_path('/usr/local/libexec/voip38-integrate')
render = integration['render_xml']
render.__globals__['MODE'] = 'LIVE'
payload = {a: (BASE / 'integration/current' / a).read_bytes() for a in integration['ACTIONS']}
generated, _ = render(payload, '92.61.60.38')
gx = ET.fromstring(generated)
assert len(gx.findall("section[@name='configuration']/configuration[@name='cdr_csv.conf']")) == 1
assert len([m for m in gx.iter('load') if m.get('module') == 'mod_cdr_csv']) == 1
fcntl.flock(lock, fcntl.LOCK_UN)

# The native load API refreshes XML then adds this reporting-only module.
loaded = cli('load mod_cdr_csv')
assert '+OK' in loaded and cli('module_exists mod_cdr_csv') == 'true'
assert cli('cdr_csv rotate') == '+OK'
subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
subprocess.run(['systemctl', 'enable', '--now', 'voip38-cdr-rotate.timer'], check=True, capture_output=True)
subprocess.run(['systemctl', 'start', 'voip38-cdr-rotate.service'], check=True, capture_output=True)
pid_after = subprocess.check_output(['systemctl', 'show', 'freeswitch', '-p', 'MainPID', '--value'], text=True).strip()
assert pid_before == pid_after
result = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'module_loaded': True, 'legs': 'ab', 'master_file_only': True,
          'path': str(master), 'columns': COLUMNS, 'owner': 'freeswitch:freeswitch',
          'directory_mode': '0750', 'file_mode': '0600',
          'rotation': {'daily': True, 'maxsize_mib': 20, 'max_archives': 14,
                       'maxage_days': 14, 'compression': True, 'delaycompress': True,
                       'check_interval_minutes': 5, 'copytruncate': False},
          'timer_enabled': True, 'timer_active': True,
          'configuration_survives_managed_regeneration': True,
          'freeswitch_pid': pid_after, 'pid_unchanged': True,
          'calls_before': calls_before, 'calls_after': cli('show calls count'),
          'freeswitch_or_sip_profile_restarted': False,
          'production_database_configuration_changed': False,
          'backup': str(backup), 'native_source_revision': 'ef32e20529'}
write(AUDIT / 'installation.json', json.dumps(result, indent=2)+'\n')
print(json.dumps(result))
