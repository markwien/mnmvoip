"""Exercise LIVE file generation in memory, never against active paths."""
import contextlib
import copy
import datetime
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import xml.etree.ElementTree as E

ROOT=Path('/root/voip50-build/live-preparation');os.umask(0o077)
loader=importlib.machinery.SourceFileLoader('live_test','/usr/local/libexec/voip50-live-runtime')
spec=importlib.util.spec_from_loader(loader.name,loader);live=importlib.util.module_from_spec(spec);loader.exec_module(live)
plan=json.loads(live.PLAN.read_text());before=json.loads((ROOT/'before.json').read_text())
class MemoryControl:
    def __init__(self,value,exists=True):self.value=value;self.present=exists
    def read_text(self):return self.value
    def exists(self):return self.present
    def stat(self):return types.SimpleNamespace(st_uid=0,st_mode=0o100600)

# Test the real root-gate path, with all authorization and network state confined
# to this process. No real commissioning/authorization file is written.
original_mode=live.MODE;original_network=live.live_network;original_commission=live.COMMISSION
original_check=live.subprocess.check_output
original_protected=live.protected
def memory_protected(path,group_read=False):
    if isinstance(path,MemoryControl):
        info=path.stat();assert info.st_uid==0 and info.st_mode & 0o077==0
    else:original_protected(path,group_read)
live.protected=memory_protected
golden=json.loads((ROOT/'expected-firewall.json').read_text())
live.MODE=MemoryControl('LIVE')
live.COMMISSION=MemoryControl(json.dumps({'vm_uuid':live.VM,'plan':plan,'authorized':True}))
live.live_network=lambda unused:True
actual=copy.deepcopy(golden);tables='table inet voip50_live\n'
def fake_check(args,**kwargs):
    if args==['nft','list','tables']:return tables
    if args==['nft','-j','list','table','inet','voip50_live']:return json.dumps(actual)
    raise AssertionError('unexpected command during in-memory gate test')
live.subprocess.check_output=fake_check
gate_cases=[]
try:
    assert live.root_gate()==plan;gate_cases.append('commissioned-restart-accepted-in-memory')
    tables+='table inet voip50_build_guard\n'
    try:live.root_gate()
    except PermissionError:gate_cases.append('remaining-build-table-rejected')
    else:raise AssertionError('unexpected firewall table accepted')
    tables='table inet voip50_live\n'
    for item in actual['nftables']:
        if item.get('chain',{}).get('name')=='input':item['chain']['policy']='accept'
    try:live.root_gate()
    except PermissionError:gate_cases.append('modified-firewall-rejected')
    else:raise AssertionError('unreviewed firewall accepted')
finally:
    live.subprocess.check_output=original_check
    live.protected=original_protected
    live.MODE=original_mode;live.COMMISSION=original_commission;live.live_network=original_network

fixture=Path(tempfile.mkdtemp(prefix='deployment-test-',dir=ROOT))
original_cache=live.CACHE;original_write=live.write;original_fetch=live.fetch
original_gate=live.root_gate;original_cache_write=live.cache_write
memory={};cached=[]
try:
    live.CACHE=fixture/'cache';live.CACHE.mkdir(mode=0o700)
    def memory_write(path,value,mode=0o600,fs_group=False,fs_owner=False):
        memory[str(path)]=(value if isinstance(value,bytes) else value.encode(),mode,fs_group)
    live.write=memory_write;live.root_gate=lambda:plan
    live.cache_write=lambda payload:cached.append(set(payload))
    def outage(*args):raise OSError('synthetic panel outage')
    live.fetch=outage
    with contextlib.redirect_stdout(io.StringIO()):live.start()
    for required in ['/etc/freeswitch/freeswitch.xml','/etc/freeswitch/voip50-live-static.xml','/etc/odbc.ini',
                     '/var/lib/freeswitch/scripts/dbconnect.lua','/root/.fs_cli_conf',
                     '/etc/voip50/live-commissioned.json','/etc/freeswitch/voip50-live-meta.json',
                     '/etc/freeswitch/voip50-live-ready']:
        assert required in memory
    assert len(cached)==1
    master=E.fromstring(memory['/etc/freeswitch/freeswitch.xml'][0])
    assert master.find("X-PRE-PROCESS[@cmd='exec']").get('data')=='/usr/local/libexec/voip50-live-runtime render'
    config=E.fromstring(memory['/etc/freeswitch/voip50-live-static.xml'][0])
    assert live.variables(config)['voip50_build_hold']=='false'
    assert memory['/etc/freeswitch/voip50-live-ready'][0].decode().strip()==live.VM
    assert memory['/etc/odbc.ini'][1:]==(0o640,True)
    assert memory['/var/lib/freeswitch/scripts/dbconnect.lua'][1:]==(0o640,True)
    assert memory['/etc/odbc.ini'][0]==(ROOT/'candidate/odbc.ini').read_bytes()
    secret=config.find("section[@name='configuration']/configuration[@name='event_socket.conf']/settings/param[@name='password']").get('value')
    assert secret in memory['/root/.fs_cli_conf'][0].decode()
finally:
    live.CACHE=original_cache;live.write=original_write;live.fetch=original_fetch
    live.root_gate=original_gate;live.cache_write=original_cache_write
    shutil.rmtree(fixture)
for path,digest in before['active_hashes'].items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
assert not live.COMMISSION.exists() and not live.READY.exists() and not live.META.exists()
result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,
        'root_gate_cases':gate_cases,'persistent_commissioning_logic_tested_in_memory':True,
        'startup_panel_outage_fallback_tested_in_memory':True,'live_file_generation_tested_in_memory':True,
        'native_callback_hook_correct':True,'esl_cli_password_matches_candidate':True,
        'odbc_and_db_wrapper_modes_correct':True,'real_active_paths_written':False,
        'real_commissioning_or_authorization_created':False,'active_build_data_unchanged':True,
        'production_db_connected':False}
(ROOT/'deployment-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
