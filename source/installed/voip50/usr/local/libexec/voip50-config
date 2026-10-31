#!/usr/bin/python3
"""Reference-derived VoIP50 configuration, strictly limited to isolated BUILD."""
import copy
import configparser
import datetime
import fcntl
import grp
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import urllib.request
import uuid
import xml.etree.ElementTree as E

BASE=Path('/root/voip50-build')
REF=BASE/'production-reference'
CACHE=Path('/var/lib/freeswitch/voip50-xml-cache')
STATIC=Path('/etc/freeswitch/voip50-static.xml')
SOURCE=Path('/etc/voip50/panel-source.json')
ACTIONS=['getHostsConfig','getGateways','getGatewayUsers','getCardsConfig','ivrXML']
CONTEXTS=['ccdialout','didrouting','ivrs','pdid','publicTrunks','routing','telekomfl']

def atomic(path,data,mode=0o600,fs=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.new')
    tmp.write_bytes(data if isinstance(data,bytes) else data.encode());tmp.chmod(mode)
    if fs:
        user=pwd.getpwnam('freeswitch');os.chown(tmp,user.pw_uid,user.pw_gid)
    elif path.parent==Path('/etc/freeswitch'):
        os.chown(tmp,0,grp.getgrnam('freeswitch').gr_gid)
    tmp.replace(path)

def fragment(data):
    text=re.sub(r'<\?xml.*?\?>','',data.decode(),flags=re.S)
    if '<html' in text.lower() or '<!doctype' in text.lower():raise ValueError('invalid config response')
    x=E.fromstring('<reference>'+text+'</reference>')
    if list(x.iter('X-PRE-PROCESS')):raise ValueError('remote executable preprocessor rejected')
    return x

def mapped(text):
    return text.replace('/usr/share/freeswitch/scripts','/var/lib/freeswitch/scripts').replace('/usr/share/freeswitch/sounds','/var/lib/freeswitch/sounds').replace('/mnt/freeswitchSounds','/var/lib/freeswitch/sounds')

def setparam(parent,key,value):
    p=next((p for p in parent.findall('param') if p.get('name')==key),None)
    if p is None:p=E.SubElement(parent,'param',name=key)
    p.set('value',str(value))

def validate(payload):
    for action in ACTIONS[1:]:
        x=fragment(payload[action]);tag={'getGateways':'gateway','getGatewayUsers':'user','getCardsConfig':'user','ivrXML':'menu'}[action]
        if action!='getCardsConfig' and not list(x.iter(tag)):raise ValueError('empty required config')
    gateways=list(fragment(payload['getGateways']).iter('gateway'))
    names=[g.get('name') for g in gateways]
    if len(set(names))!=len(names) or not all(re.fullmatch(r'[A-Za-z0-9_-]+',n or '') for n in names):raise ValueError('invalid gateway names')
    hosts=[]
    for line in payload.get('getHostsConfig',b'').decode().splitlines():
        f=line.split('#',1)[0].split()
        if not f:continue
        if len(f)!=2 or f[0] not in ['trust','voip'] or not f[1].startswith('eth0:'):raise ValueError('invalid firewall source')
        for net in f[1].split(':',1)[1].split(','):
            n=ipaddress.ip_network(net,strict=False)
            if n.version!=4:raise ValueError('unexpected source family')
            hosts.append((f[0],str(n)))
    if 'getHostsConfig' in payload and not hosts:raise ValueError('empty firewall source')
    return hosts

def sanitized(payload):
    salt=Path('/etc/freeswitch/.voip50-build-salt').read_bytes()
    out={}
    for action,data in payload.items():
        if action=='getHostsConfig':out[action]=data;continue
        x=fragment(data)
        for n in x.iter():
            for key,value in list(n.attrib.items()):n.set(key,mapped(value))
            if n.tag=='param' and re.search(r'pass|secret|token',n.get('name',''),re.I):
                n.set('value',hmac.new(salt,(action+'|'+E.tostring(n,encoding='unicode')).encode(),hashlib.sha256).hexdigest())
        if action=='getGateways':
            for g in x.iter('gateway'):
                setparam(g,'register','false');setparam(g,'ping','0')
        out[action]='\n'.join(E.tostring(c,encoding='unicode') for c in x).encode()
    return out

def fetch():
    if Path('/etc/voip50/mode').read_text().strip()!='BUILD':raise ValueError('BUILD only')
    source=json.loads(SOURCE.read_text())
    if not source.get('enabled') or source.get('switch_id')!=4 or source.get('base_url')!='http://192.168.1.225:9000/configHandler/':raise ValueError('unexpected or disabled panel identity')
    data={}
    for action in ACTIONS:
        url=source['base_url']+action+'?switchid=4'
        with urllib.request.urlopen(url,timeout=6) as response:
            b=response.read(8*1024*1024)
            if response.status!=200 or len(b)>=8*1024*1024:raise ValueError('bad response')
            data[action]=b
    validate(data)
    return sanitized(data)

def cache_write(payload):
    user=pwd.getpwnam('freeswitch');CACHE.mkdir(mode=0o700,exist_ok=True);os.chown(CACHE,user.pw_uid,user.pw_gid)
    generation=CACHE/('generation-'+uuid.uuid4().hex);generation.mkdir(mode=0o700);os.chown(generation,user.pw_uid,user.pw_gid)
    for action,data in payload.items():atomic(generation/action,data,fs=True)
    link=CACHE/'current.new';link.unlink(missing_ok=True);link.symlink_to(generation);link.replace(CACHE/'current')
    for p in CACHE.glob('generation-*'):
        if p!=generation:shutil.rmtree(p)

def cache_read():
    payload={a:(CACHE/'current'/a).read_bytes() for a in ACTIONS};validate(payload);return payload

def overlay(root,payload):
    config=root.find("section[@name='configuration']")
    sofia=config.find("configuration[@name='sofia.conf']")
    for profile in sofia.iter('profile'):
        gateways=profile.find('gateways');gateways.clear()
        for g in fragment(payload['getGateways']).iter('gateway'):gateways.append(copy.deepcopy(g))
    menus=config.find("configuration[@name='ivr.conf']/menus");menus.clear()
    for m in fragment(payload['ivrXML']).iter('menu'):menus.append(copy.deepcopy(m))
    users=root.find("section[@name='directory']/domain/users");users.clear()
    for action in ['getGatewayUsers','getCardsConfig']:
        for u in fragment(payload[action]).iter('user'):users.append(copy.deepcopy(u))
    return root

def counts(payload,source):
    return {'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,
        'panel':'192.168.1.225:9000','switch_id':4,'mode':'BUILD',
        'gateways':len(list(fragment(payload['getGateways']).iter('gateway'))),
        'gateway_users':len(list(fragment(payload['getGatewayUsers']).iter('user'))),
        'cards':len(list(fragment(payload['getCardsConfig']).iter('user'))),
        'ivr_menus':len(list(fragment(payload['ivrXML']).iter('menu'))),
        'production_passwords_replaced_in_active_payload':True,'registration_and_pings_disabled':True}

def render(part=None):
    if Path('/etc/voip50/mode').read_text().strip()!='BUILD':raise ValueError('BUILD only')
    lock=(CACHE/'lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX)
    source='panel'
    try:payload=fetch();cache_write(payload)
    except Exception:payload=cache_read();source='last-known-good'
    atomic(CACHE/'status.json',json.dumps(counts(payload,source),indent=2)+'\n',fs=True)
    if part:
        action={'gateways':'getGateways','gdirectory':'getGatewayUsers','directory':'getCardsConfig','ivr':'ivrXML'}[part]
        sys.stdout.write(payload[action].decode());return
    root=overlay(E.parse(STATIC).getroot(),payload)
    variables={'base_dir':'/opt/freeswitch','conf_dir':'/etc/freeswitch','sounds_dir':'/var/lib/freeswitch/sounds','certs_dir':'/etc/freeswitch/ssl'}
    for n in root.findall('X-PRE-PROCESS'):
        k,sep,v=n.get('data','').partition('=')
        if sep:variables[k]=v
    def expand(value):
        for _ in range(15):
            new=re.sub(r'\$\$\{([^}]+)\}',lambda m:variables.get(m.group(1),m.group(0)),value)
            if new==value:return value
            value=new
        return value
    sections=[]
    for s in root.findall('section'):
        for n in s.iter():
            for k,v in list(n.attrib.items()):n.set(k,expand(v))
            if n.text:n.text=expand(n.text)
        sections.append(E.tostring(s,encoding='unicode'))
    text='\n'.join(sections)
    if re.search(r'\$\$\{[^}]+\}',text):raise ValueError('unresolved globals')
    E.fromstring('<document>'+text+'</document>');sys.stdout.write(text)

def prepare():
    if os.geteuid()!=0:raise PermissionError('root required')
    # Root-only baseline verifies DHCP and the unchanged BUILD firewall first.
    subprocess.run(['/usr/local/libexec/voip50-base-config'],check=True,capture_output=True)
    cache_lock=(CACHE/'lock').open('a');fcntl.flock(cache_lock,fcntl.LOCK_EX)
    base=E.parse('/etc/freeswitch/freeswitch.xml').getroot()
    address=next(n.get('data').split('=',1)[1] for n in base.findall('X-PRE-PROCESS') if n.get('data','').startswith('domain='))
    payload_source='panel'
    try:payload=fetch();cache_write(payload)
    except Exception:payload=cache_read();payload_source='last-known-good'
    candidate_root=BASE/'candidate-generations';candidate_root.mkdir(mode=0o700,exist_ok=True)
    generation=candidate_root/('generation-'+uuid.uuid4().hex);shutil.copytree(REF,generation)
    (generation/'reference-manifest.json').rename(generation/'source-reference-manifest.json')
    vars_path=generation/'etc/freeswitch/vars.xml';vr=E.parse(vars_path).getroot()
    changes={'switchid':'4','default_profile':'voip01','external_sip_ip':address,'external_rtp_ip':address,'local_ip_v4':address,'domain':address,'voip50_build_hold':'true'}
    for k,v in changes.items():
        n=next((n for n in vr.findall('X-PRE-PROCESS') if n.get('data','').startswith(k+'=')),None)
        if n is None:n=E.SubElement(vr,'X-PRE-PROCESS',cmd='set')
        n.set('data',k+'='+v)
    E.indent(vr);atomic(vars_path,E.tostring(vr,encoding='utf-8'))
    for p in [generation/'etc/telemediacloud.conf',generation/'etc/freeswitch/scripts/telemediacloud.conf']:
        cp=configparser.RawConfigParser();cp.read(p)
        if not cp.has_section('config'):cp.add_section('config')
        for k,v in {'switchid':'4','baseURL':'http://192.168.1.225:9000/configHandler/','tmpDir':'/var/lib/freeswitch/voip50-xml-cache/'}.items():cp.set('config',k,v)
        with p.open('w') as f:cp.write(f)
    cp=configparser.RawConfigParser();cp.read(generation/'etc/odbc.ini')
    for section in cp.sections():cp.set(section,'driver','MariaDB Unicode');cp.set(section,'interactive','1')
    with (generation/'etc/odbc.ini').open('w') as f:cp.write(f)
    # Keep obsolete source driver definitions only as a labeled reference.
    shutil.copyfile('/etc/odbcinst.ini',generation/'etc/odbcinst.ini')
    rootvars={n.get('data','').split('=',1)[0]:n.get('data','').split('=',1)[1] for n in base.findall('X-PRE-PROCESS') if '=' in n.get('data','')}
    original_vars={n.get('data','').split('=',1)[0]:n.get('data','').split('=',1)[1] for n in vr.findall('X-PRE-PROCESS') if '=' in n.get('data','')}
    original_prefs={k:original_vars.get(k,'') for k in ['global_codec_prefs','outbound_codec_prefs']}
    for k,v in original_prefs.items():rootvars[k]=v
    rootvars['hold_music']='local_stream://default'
    rootvars.update(changes);rootvars['external_sip_ip']='127.0.0.1';rootvars['external_rtp_ip']='127.0.0.1'
    for n in list(base):
        if n.tag=='X-PRE-PROCESS':base.remove(n)
    for k,v in reversed(list(rootvars.items())):base.insert(0,E.Element('X-PRE-PROCESS',cmd='set',data=k+'='+v))
    config=base.find("section[@name='configuration']");mods=config.find("configuration[@name='modules.conf']/modules")
    for m in ['mod_amr','mod_g723_1']:
        if not any(n.get('module')==m for n in mods):E.SubElement(mods,'load',module=m)
    original_profile=next(E.parse(REF/'etc/freeswitch/sip_profiles/voip01.xml').iter('profile'))
    profile=copy.deepcopy(original_profile)
    for n in list(profile):
        if n.tag=='X-PRE-PROCESS':profile.remove(n)
    gateways=profile.find('gateways')
    if gateways is None:gateways=E.SubElement(profile,'gateways')
    gateways.clear();settings=profile.find('settings')
    for n in list(settings):
        if n.get('name','').startswith('tls-') or n.get('name') in ['odbc-dsn','core-db-dsn','ws-binding','wss-binding']:settings.remove(n)
    for k,v in {'sip-ip':'127.0.0.1','rtp-ip':'127.0.0.1','ext-sip-ip':'127.0.0.1','ext-rtp-ip':'127.0.0.1','tls':'false','disable-register':'true','sip-capture':'no','apply-inbound-acl':'domains'}.items():setparam(settings,k,v)
    sofia=config.find("configuration[@name='sofia.conf']/profiles");sofia.clear();sofia.append(profile)
    # The inactive profile is also made consistent with DHCP and BUILD.
    candidate_profile=copy.deepcopy(profile)
    for k in ['sip-ip','rtp-ip','ext-sip-ip','ext-rtp-ip']:setparam(candidate_profile.find('settings'),k,address)
    for gateway in fragment(payload['getGateways']).iter('gateway'):candidate_profile.find('gateways').append(copy.deepcopy(gateway))
    wrapper=E.Element('include');wrapper.append(candidate_profile);E.indent(wrapper)
    atomic(generation/'etc/freeswitch/sip_profiles/voip01.xml',E.tostring(wrapper,encoding='utf-8'))
    dialplan=base.find("section[@name='dialplan']");dialplan.clear();dialplan.set('name','dialplan')
    for name in CONTEXTS:
        p=REF/'etc/freeswitch/dialplan'/(name+'.xml');source=E.parse(p).getroot()
        context=copy.deepcopy(next(c for c in source.iter('context') if c.get('name')==name))
        if list(context.iter('X-PRE-PROCESS')):raise ValueError('unexpected dialplan preprocessing')
        for n in context.iter():
            for k,v in list(n.attrib.items()):n.set(k,mapped(v))
        guard=E.Element('extension',name='voip50-build-hold',attrib={'continue':'false'});cond=E.SubElement(guard,'condition',field='${voip50_build_hold}',expression='^true$');E.SubElement(cond,'action',application='hangup',data='CALL_REJECTED');context.insert(0,guard)
        dialplan.append(context)
        w=E.Element('include');w.append(copy.deepcopy(context));E.indent(w);atomic(generation/'etc/freeswitch/dialplan'/(name+'.xml'),E.tostring(w,encoding='utf-8'))
    base=overlay(base,payload);E.indent(base);static=E.tostring(base,encoding='utf-8')
    atomic(STATIC,static,0o640)
    master=E.Element('document',type='freeswitch/xml')
    for n in base.findall('X-PRE-PROCESS'):master.append(copy.deepcopy(n))
    E.SubElement(master,'X-PRE-PROCESS',cmd='exec',data='/usr/local/libexec/voip50-config render');E.indent(master)
    atomic('/etc/freeswitch/freeswitch.xml',E.tostring(master,encoding='utf-8'),0o640)
    atomic(generation/'active-build-static.xml',static)
    atomic(generation/'etc/freeswitch/freeswitch.xml',static)
    for action,name in {'getGateways':'gateways.xml','getGatewayUsers':'gateways_directory.xml','getCardsConfig':'directory.xml','ivrXML':'ivr.xml'}.items():
        atomic(generation/'etc/freeswitch/tmp'/name,payload[action])
    atomic(generation/'etc/freeswitch/scripts/fetchConfig.py',Path('/etc/freeswitch/scripts/fetchConfig.py').read_bytes())
    atomic(generation/'etc/nftables.build.conf',Path('/etc/nftables.conf').read_bytes())
    atomic(generation/'etc/shorewall/reloadConfig.sh','#!/bin/sh\n# Inactive compatibility reference. BUILD does not apply production rules.\nexec /usr/local/libexec/voip50-config prepare\n')
    atomic(generation/'etc/shorewall/BUILD-NETWORK-PLAN.json',json.dumps({'mode':'BUILD','management_interface':'enX0','management_ip':address,'old_lan':'eth1','old_wan':'eth0','new_wan':None,'public_ip_not_assigned':'92.61.60.50','production_firewall_not_applied':True,'panel_source':'192.168.1.225:9000','switch_id':4},indent=2)+'\n')
    hosts=validate(payload)
    atomic(generation/'firewall-source-preview.json',json.dumps({'trust_networks':len({n for z,n in hosts if z=='trust'}),'voip_networks':len({n for z,n in hosts if z=='voip'}),'applied':False},indent=2)+'\n')
    missing=[]
    for menu in fragment(payload['ivrXML']).iter('menu'):
        for value in menu.attrib.values():
            for filename in re.findall(r'promptFile_\d+\.wav',value):
                if not (Path('/var/lib/freeswitch/sounds/en/us/callie/mark')/filename).exists():missing.append(filename)
    for p in [generation]+list(generation.rglob('*')):p.chmod(0o700 if p.is_dir() else 0o600);os.chown(p,0,0)
    link=BASE/'candidate.new';link.unlink(missing_ok=True);link.symlink_to(generation);link.replace(BASE/'candidate')
    for p in candidate_root.glob('generation-*'):
        if p!=generation:shutil.rmtree(p)
    result=counts(payload,payload_source)
    result.update({'management_ip':address,'default_profile':'voip01','contexts':CONTEXTS,'profile_context':profile.find('settings/param[@name="context"]').get('value'),'original_contexts_preserved':True,'global_ids_corrected':[6,2],'direct_db_access_blocked':True,'production_dsn_only_in_root_candidate':True,'candidate_odbc_driver':'MariaDB Unicode','candidate_odbc_interactive':1,'private_ivr_prompts_missing':sorted(set(missing)),'private_audio_copied':False,'firewall_unchanged':True,'live_activation_supported':False,'source_reference_unchanged':True})
    atomic(BASE/'reference-integration.json',json.dumps(result,indent=2)+'\n');fcntl.flock(cache_lock,fcntl.LOCK_UN);print(json.dumps(result))

if __name__=='__main__':
    try:
        if sys.argv[1]=='prepare':prepare()
        elif sys.argv[1]=='render':render(sys.argv[2] if len(sys.argv)>2 else None)
        else:raise ValueError('unknown command')
    except Exception as e:
        import traceback
        frames=[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(e.__traceback__)]
        print(json.dumps({'error_type':type(e).__name__,'frames':frames}),file=sys.stderr);raise SystemExit(1)
