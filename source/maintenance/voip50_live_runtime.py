#!/usr/bin/python3
"""Prepare LIVE privately; deployment requires identity, firewall and authorization."""
import configparser
import copy
import datetime
import fcntl
import grp
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as E

ROOT=Path('/root/voip50-build/live-preparation')
REF=Path('/root/voip50-build/production-reference/etc/freeswitch')
MODE=Path('/etc/voip50/mode')
PLAN=Path('/etc/voip50/network-plan.json')
COMMISSION=Path('/etc/voip50/live-commissioned.json')
META=Path('/etc/freeswitch/voip50-live-meta.json')
READY=Path('/etc/freeswitch/voip50-live-ready')
STATIC=Path('/etc/freeswitch/voip50-live-static.xml')
CACHE=Path('/var/lib/freeswitch/voip50-live-xml-cache')
BASE_URL='http://192.168.1.225:9000/configHandler/'
VM='3558e997-ebeb-1667-beab-52cda40ec3cf'
CONTEXTS=['ccdialout','didrouting','ivrs','pdid','publicTrunks','routing','telekomfl']
ACTIONS=['getHostsConfig','getGateways','getGatewayUsers','getCardsConfig','ivrXML']

def load(path,name):
    loader=importlib.machinery.SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module

build=load('/usr/local/libexec/voip50-config','voip50_build')

def write(path,value,mode=0o600,fs_group=False,fs_owner=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.new')
    temp.write_bytes(value if isinstance(value,bytes) else value.encode());temp.chmod(mode)
    user=pwd.getpwnam('freeswitch')
    os.chown(temp,user.pw_uid if fs_owner else 0,user.pw_gid if fs_group or fs_owner else 0)
    temp.replace(path)

def protected(path,group_read=False):
    info=Path(path).stat()
    if info.st_uid!=0 or info.st_mode & (0o027 if group_read else 0o077):
        raise PermissionError('unprotected control file')

def fetch(include_hosts=True):
    payload={}
    for action in ACTIONS if include_hosts else ACTIONS[1:]:
        with urllib.request.urlopen(BASE_URL+action+'?switchid=4',timeout=6) as response:
            data=response.read(8*1024*1024)
            if response.status!=200 or len(data)>=8*1024*1024:raise ValueError('bad panel response')
            payload[action]=data
    build.validate(payload)
    # Map paths but retain the real panel credentials and registration settings.
    for action in ACTIONS[1:]:
        root=build.fragment(payload[action])
        for node in root.iter():
            for key,value in list(node.attrib.items()):node.set(key,build.mapped(value))
        payload[action]='\n'.join(E.tostring(c,encoding='unicode') for c in root).encode()
    return payload

def variables(root):
    return {n.get('data').split('=',1)[0]:n.get('data').split('=',1)[1]
            for n in root.findall('X-PRE-PROCESS') if n.get('cmd')=='set' and '=' in n.get('data','')}

def assemble(base,payload,reference,plan):
    root=copy.deepcopy(base);configuration=root.find("section[@name='configuration']")
    values=variables(root);values.update(variables(E.parse(reference/'vars.xml').getroot()))
    address=plan['public']['address']
    values.update({'switchid':'4','default_profile':'voip01','domain':address,'local_ip_v4':address,
                   'external_sip_ip':address,'external_rtp_ip':address,'voip50_build_hold':'false',
                   'sound_prefix':'/var/lib/freeswitch/sounds/en/us/callie',
                   'base_dir':'/opt/freeswitch','conf_dir':'/etc/freeswitch',
                   'sounds_dir':'/var/lib/freeswitch/sounds','certs_dir':'/etc/freeswitch/ssl'})
    for node in list(root):
        if node.tag=='X-PRE-PROCESS':root.remove(node)
    for key,value in reversed(list(values.items())):root.insert(0,E.Element('X-PRE-PROCESS',cmd='set',data=key+'='+value))
    for name in ['acl.conf','event_socket.conf']:
        current=configuration.find("configuration[@name='"+name+"']")
        original=next(E.parse(reference/'autoload_configs'/(name+'.xml')).iter('configuration'))
        configuration.remove(current);configuration.append(copy.deepcopy(original))
    esl=configuration.find("configuration[@name='event_socket.conf']/settings")
    for key,value in {'listen-ip':'0.0.0.0','listen-port':'8021','nat-map':'false','apply-inbound-acl':'esl'}.items():build.setparam(esl,key,value)
    acl=configuration.find("configuration[@name='acl.conf']/network-lists")
    for name in ['esl','domains']:
        entry=acl.find("list[@name='"+name+"']")
        if entry is None or entry.get('default')!='deny':raise ValueError('missing restrictive ACL')
        if any(node.get('cidr')=='0.0.0.0/0' and node.get('type')=='allow' for node in entry):raise ValueError('open ACL')
    domains=acl.find("list[@name='domains']")
    for cidr in ['127.0.0.1/32',address+'/32']:
        if not any(n.get('cidr')==cidr for n in domains):E.SubElement(domains,'node',type='allow',cidr=cidr)
    original_settings=next(E.parse(reference/'sip_profiles/voip01.xml').iter('profile')).find('settings')
    for profile in configuration.find("configuration[@name='sofia.conf']").iter('profile'):
        settings=profile.find('settings')
        for key in ['sip-ip','rtp-ip','ext-sip-ip','ext-rtp-ip']:build.setparam(settings,key,address)
        for node in list(settings):
            if node.get('name')=='disable-register':settings.remove(node)
        for node in original_settings:
            if node.get('name')=='disable-register':settings.append(copy.deepcopy(node))
        build.setparam(settings,'tls','false')
    directory=root.find("section[@name='directory']/domain");directory.set('name',address)
    for context in root.findall("section[@name='dialplan']/context"):
        for extension in list(context):
            if extension.get('name')=='voip50-build-hold':context.remove(extension)
    cdr=configuration.find("configuration[@name='cdr_csv.conf']/templates/template[@name='voip50-local']")
    assert cdr is not None and '"voip-50-build","4","192.168.1.217"' in cdr.text
    cdr.text=cdr.text.replace('"voip-50-build","4","192.168.1.217"','"voip-50","4","92.61.60.50"')
    build.overlay(root,payload)
    E.indent(root);return root

def expanded(root,payload):
    root=build.overlay(copy.deepcopy(root),payload);values=variables(root)
    def expand(text):
        for _ in range(20):
            changed=re.sub(r'\$\$\{([^}]+)\}',lambda m:values.get(m.group(1),m.group(0)),text)
            if changed==text:return changed
            text=changed
        return text
    sections=[]
    for section in root.findall('section'):
        for node in section.iter():
            for key,value in list(node.attrib.items()):node.set(key,expand(value))
            if node.text:node.text=expand(node.text)
        sections.append(E.tostring(section,encoding='unicode'))
    result='\n'.join(sections)
    if re.search(r'\$\$\{[^}]+\}',result):raise ValueError('unresolved LIVE global')
    E.fromstring('<document>'+result+'</document>');return result

def normalized(value):
    if isinstance(value,dict):return {k:normalized(v) for k,v in value.items() if k not in ['handle','metainfo']}
    if isinstance(value,list):return [normalized(v) for v in value if not (isinstance(v,dict) and 'metainfo' in v)]
    return value

def network_identity(plan,addresses,route):
    if plan['new_vm_uuid']!=VM:raise ValueError('wrong VM plan')
    by_name={item['ifname']:item for item in addresses}
    if plan['internal']['interface']==plan['public']['interface']:raise ValueError('overlapping network roles')
    for role in ['internal','public']:
        expected=plan[role];actual=by_name[expected['interface']]
        if actual['address'].lower()!=expected['mac'].lower():raise ValueError('MAC mismatch')
        ips={(a['local'],a['prefixlen']) for a in actual.get('addr_info',[]) if a.get('family')=='inet'}
        if ips!={(expected['address'],expected['prefix'])}:raise ValueError('production IP/prefix mismatch')
    if len(route)!=1 or route[0].get('gateway')!=plan['public']['gateway'] or route[0]['dev']!=plan['public']['interface']:raise ValueError('public default route mismatch')
    return True

def proof_valid(plan,proof,now):
    if not all(proof.get(k) is True for k in ['user_authorized_live','old_vm_halted','old_vifs_inactive']):raise PermissionError('cutover proof missing')
    if proof.get('new_vm_uuid')!=VM or proof.get('old_vm_uuid')!=plan['old_vm_uuid']:raise PermissionError('cutover VM identity mismatch')
    if not 0<=now-proof.get('checked_epoch',0)<900:raise PermissionError('cutover proof expired')
    return True

def live_network(plan):
    return network_identity(plan,json.loads(subprocess.check_output(['ip','-j','addr'],text=True)),json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True)))

def root_gate():
    if os.geteuid()!=0 or MODE.read_text().strip()!='LIVE':raise PermissionError('LIVE startup is not enabled')
    protected(PLAN);plan=json.loads(PLAN.read_text());live_network(plan)
    if COMMISSION.exists():
        protected(COMMISSION);commission=json.loads(COMMISSION.read_text())
        if commission.get('vm_uuid')!=VM or commission.get('plan')!=plan or commission.get('authorized') is not True:raise PermissionError('invalid persistent commissioning')
    else:
        proof=Path('/root/voip50-build/cutover/authorization.json');protected(proof)
        proof_valid(plan,json.loads(proof.read_text()),time.time())
    tables=subprocess.check_output(['nft','list','tables'],text=True).splitlines()
    if set(tables)!={'table inet voip50_live'}:raise PermissionError('firewall is not in the reviewed LIVE state')
    expected=json.loads((ROOT/'expected-firewall.json').read_text())
    actual=json.loads(subprocess.check_output(['nft','-j','list','table','inet','voip50_live'],text=True))
    if normalized(actual)!=expected:raise PermissionError('LIVE firewall differs from reviewed candidate')
    return plan

def prepare_build():
    if os.geteuid()!=0 or MODE.read_text().strip()!='BUILD':raise PermissionError('BUILD/root required')
    assets=ROOT/'build-assets'
    for source,target,group in [('odbc.ini','/etc/odbc.ini',True),
                                ('dbconnect.lua','/var/lib/freeswitch/scripts/dbconnect.lua',True),
                                ('local-esl.json','/root/voip50-build/local-esl.json',False),
                                ('fs_cli.conf','/root/.fs_cli_conf',False)]:
        write(target,(assets/source).read_bytes(),0o640 if group else 0o600,fs_group=group)
    for path in [COMMISSION,META,READY,STATIC]:path.unlink(missing_ok=True)
    if CACHE.exists():shutil.rmtree(CACHE)
    subprocess.run(['/usr/local/libexec/voip50-config','prepare'],check=True)

def cache_write(payload):
    user=pwd.getpwnam('freeswitch');CACHE.mkdir(mode=0o700,exist_ok=True);CACHE.chmod(0o700);os.chown(CACHE,user.pw_uid,user.pw_gid)
    generation=CACHE/('generation-'+uuid.uuid4().hex);generation.mkdir(mode=0o700);os.chown(generation,user.pw_uid,user.pw_gid)
    for action in ACTIONS[1:]:write(generation/action,payload[action],fs_owner=True)
    temp=CACHE/'current.new';temp.unlink(missing_ok=True);temp.symlink_to(generation);temp.replace(CACHE/'current')
    for path in CACHE.glob('generation-*'):
        if path!=generation:shutil.rmtree(path)

def native_gate():
    if MODE.read_text().strip()!='LIVE':raise PermissionError('LIVE renderer blocked in BUILD')
    for path in [META,READY,STATIC]:protected(path,group_read=True)
    meta=json.loads(META.read_text())
    if meta.get('vm_uuid')!=VM or READY.read_text().strip()!=VM:raise PermissionError('runtime not commissioned')
    live_network(meta['plan']);return meta

def render(part=None):
    native_gate();lock=(CACHE/'lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX)
    source='panel'
    try:payload=fetch(False);cache_write(payload)
    except Exception:
        payload={a:(CACHE/'current'/a).read_bytes() for a in ACTIONS[1:]};build.validate(payload);source='last-known-good'
    write(CACHE/'status.json',json.dumps({'source':source,'switch_id':4,'mode':'LIVE','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})+'\n',fs_owner=True)
    if part:
        sys.stdout.write(payload[{'gateways':'getGateways','gdirectory':'getGatewayUsers','directory':'getCardsConfig','ivr':'ivrXML'}[part]].decode())
    else:sys.stdout.write(expanded(E.parse(STATIC).getroot(),payload))

def master(root):
    result=E.Element('document',type='freeswitch/xml')
    for node in root.findall('X-PRE-PROCESS'):result.append(copy.deepcopy(node))
    E.SubElement(result,'X-PRE-PROCESS',cmd='exec',data='/usr/local/libexec/voip50-live-runtime render')
    E.indent(result);return E.tostring(result,encoding='utf-8')

def preview():
    if os.geteuid()!=0 or MODE.read_text().strip()!='BUILD':raise PermissionError('preview requires BUILD/root')
    plan=json.loads(PLAN.read_text());payload=fetch()
    root=assemble(E.parse('/etc/freeswitch/voip50-static.xml').getroot(),payload,REF,plan)
    # This parse/expansion stays root-only and never reaches the running daemon.
    expanded(root,payload)
    generation=ROOT/('generation-'+uuid.uuid4().hex);generation.mkdir(mode=0o700)
    for action,data in payload.items():write(generation/'payload'/action,data)
    write(generation/'static.xml',E.tostring(root,encoding='utf-8'))
    write(generation/'master.xml',master(root))
    write(generation/'dbconnect.lua',(ROOT/'source/voip50_live_dbconnect.lua').read_bytes())
    write(generation/'odbc.ini',Path('/root/voip50-build/candidate/etc/odbc.ini').read_bytes())
    vals=variables(root);config=configparser.RawConfigParser();config.read(generation/'odbc.ini')
    if {vals.get('db1DSN'),vals.get('db2DSN')}!={'freeswitch155','freeswitch146'}:raise ValueError('unexpected DSN mapping')
    for i in ['1','2']:
        dsn=vals['db'+i+'DSN']
        if vals.get('db'+i+'User')!=config[dsn]['user'] or vals.get('db'+i+'Pass')!=config[dsn]['password']:raise ValueError('ODBC/global credentials disagree')
    link=ROOT/'candidate.new';link.unlink(missing_ok=True);link.symlink_to(generation);link.replace(ROOT/'candidate')
    for path in ROOT.glob('generation-*'):
        if path!=generation:shutil.rmtree(path)
    esl=root.find("section[@name='configuration']/configuration[@name='event_socket.conf']/settings/param[@name='password']")
    if esl is None or not esl.get('value'):raise ValueError('missing legacy ESL password')
    result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'mode':'BUILD','live_preview_created':True,
            'switch_id':4,'public_address':plan['public']['address'],'internal_address':plan['internal']['address'],
            'panel':'192.168.1.225:9000','profile':'voip01','profile_context':'telekomfl',
            'gateways':len(list(build.fragment(payload['getGateways']).iter('gateway'))),
            'gateway_users':len(list(build.fragment(payload['getGatewayUsers']).iter('user'))),
            'ivr_menus':len(list(build.fragment(payload['ivrXML']).iter('menu'))),
            'esl_legacy_password_retained':True,'esl_legacy_acl_retained':True,
            'odbc_globals_credentials_match':True,'odbc_interactive':1,
            'both_dsn_servers':[config[s]['server'] for s in config.sections()],
            'db_selector_to_dsn':{i:vals['db'+i+'DSN'] for i in ['1','2']},
            'live_cdr_label':'voip-50 / 4 / 92.61.60.50','production_db_connected':False,
            'live_cache_isolated_from_build':True,'candidate_root_only':True,'live_activated':False}
    write(ROOT/'preview-status.json',json.dumps(result,indent=2)+'\n');print(json.dumps(result))

def start():
    plan=root_gate()
    # First boot and restart use the last reviewed private candidate as fallback.
    candidate=(ROOT/'candidate').resolve()
    source='panel'
    try:payload=fetch()
    except Exception:
        fallback=CACHE/'current' if (CACHE/'current').exists() else candidate/'payload'
        payload={a:(fallback/a).read_bytes() for a in ACTIONS[1:]};build.validate(payload);source='last-known-good'
    root=build.overlay(E.parse(candidate/'static.xml').getroot(),payload);expanded(root,payload)
    cache_write(payload)
    lock=CACHE/'lock';lock.touch(exist_ok=True);lock.chmod(0o600);os.chown(lock,pwd.getpwnam('freeswitch').pw_uid,grp.getgrnam('freeswitch').gr_gid)
    write(STATIC,E.tostring(root,encoding='utf-8'),0o640,fs_group=True)
    write('/etc/freeswitch/freeswitch.xml',master(root),0o640,fs_group=True)
    write('/etc/odbc.ini',(candidate/'odbc.ini').read_bytes(),0o640,fs_group=True)
    write('/var/lib/freeswitch/scripts/dbconnect.lua',(candidate/'dbconnect.lua').read_bytes(),0o640,fs_group=True)
    secret=root.find("section[@name='configuration']/configuration[@name='event_socket.conf']/settings/param[@name='password']").get('value')
    write('/root/.fs_cli_conf','[default]\nhost => 127.0.0.1\nport => 8021\npassword => '+secret+'\n')
    write('/root/voip50-build/local-esl.json',json.dumps({'password':secret}))
    write(COMMISSION,json.dumps({'vm_uuid':VM,'plan':plan,'authorized':True},indent=2)+'\n')
    write(META,json.dumps({'vm_uuid':VM,'plan':plan,'source':BASE_URL,'switch_id':4}),0o640,fs_group=True)
    write(READY,VM+'\n',0o640,fs_group=True)
    print(json.dumps({'prepared_for_live_start':True,'source':source,'switch_id':4}))

if __name__=='__main__':
    try:
        os.umask(0o077)
        if sys.argv[1]=='preview':preview()
        elif sys.argv[1]=='build':prepare_build()
        elif sys.argv[1]=='start':start()
        elif sys.argv[1]=='render':render(sys.argv[2] if len(sys.argv)>2 else None)
        else:raise ValueError('unknown command')
    except Exception as error:
        # Never include credential-bearing XML, connection strings or exception messages.
        print(json.dumps({'error_type':type(error).__name__,'live_activated':False}),file=sys.stderr)
        raise SystemExit(1)
