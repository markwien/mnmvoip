#!/usr/bin/python3
"""Generate a new, credential-isolated BUILD config; never activate production."""
from pathlib import Path
import grp
import ipaddress
import json
import os
import subprocess
import xml.etree.ElementTree as E

MODE = Path('/etc/voip50/mode').read_text().strip()
if MODE != 'BUILD':
    raise SystemExit('This build renderer cannot activate LIVE mode')
addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'], text=True))
ips = [a['local'] for d in addresses if d['ifname'] != 'lo' for a in d.get('addr_info', []) if a.get('family') == 'inet']
if len(ips) != 1 or ipaddress.ip_address(ips[0]) not in ipaddress.ip_network('192.168.1.0/24') or ips[0] in ['192.168.1.38','192.168.1.50']:
    raise SystemExit('BUILD requires one separate management LAN address')
fw = subprocess.check_output(['nft', 'list', 'table', 'inet', 'voip50_build'], text=True)
if fw.count('policy drop;') < 2 or not all(str(port) in fw for port in [3306,5060,5061,8021]) or 'reject' not in fw:
    raise SystemExit('BUILD firewall not ready')
secret = json.loads(Path('/root/voip50-build/local-esl.json').read_text())['password']
root = E.Element('document', type='freeswitch/xml')
for k,v in {'default_profile':'voip01','switchid':'4','domain':ips[0],
            'local_ip_v4':ips[0],'external_sip_ip':'127.0.0.1','external_rtp_ip':'127.0.0.1',
            'voip50_build_hold':'true','sound_prefix':'/var/lib/freeswitch/sounds/en/us/callie',
            'global_codec_prefs':'PCMA,PCMU,G729','outbound_codec_prefs':'PCMA,PCMU,G729'}.items():
    E.SubElement(root,'X-PRE-PROCESS',cmd='set',data=k+'='+v)
cs = E.SubElement(root,'section',name='configuration')
def conf(name):return E.SubElement(cs,'configuration',name=name)
def settings(parent,values,tag='settings'):
    s=E.SubElement(parent,tag)
    for k,v in values.items():E.SubElement(s,'param',name=k,value=str(v))
    return s
mods=E.SubElement(conf('modules.conf'),'modules')
for m in ['mod_logfile','mod_commands','mod_event_socket','mod_dptools','mod_dialplan_xml',
          'mod_sofia','mod_loopback','mod_lua','mod_hash','mod_sndfile','mod_tone_stream',
          'mod_spandsp','mod_bcg729','mod_native_file','mod_local_stream','mod_say_en','mod_cdr_csv']:
    E.SubElement(mods,'load',module=m)
settings(conf('switch.conf'),{'loglevel':'notice','rtp-start-port':'40000','rtp-end-port':'60000',
          'max-sessions':'100','sessions-per-second':'10','min-idle-cpu':'0'})
log=E.SubElement(E.SubElement(conf('logfile.conf'),'profiles'),'profile',name='default')
settings(log,{'logfile':'/var/log/freeswitch/freeswitch.log','rollover':'10485760','maximum-rotate':'7'})
E.SubElement(E.SubElement(log,'mappings'),'map',name='all',value='warning,err,crit,alert')
settings(conf('event_socket.conf'),{'listen-ip':'127.0.0.1','listen-port':'8021','password':secret,
          'apply-inbound-acl':'esl','nat-map':'false'})
lists=E.SubElement(conf('acl.conf'),'network-lists')
for name in ['esl','domains','lan']:
    n=E.SubElement(lists,'list',name=name,default='deny')
    E.SubElement(n,'node',type='allow',cidr='127.0.0.1/32')
sofia=conf('sofia.conf')
settings(sofia,{'auto-restart':'false'},tag='global_settings')
profile=E.SubElement(E.SubElement(sofia,'profiles'),'profile',name='voip01')
E.SubElement(profile,'aliases');E.SubElement(profile,'gateways')
settings(profile,{'sip-ip':'127.0.0.1','rtp-ip':'127.0.0.1','ext-sip-ip':'127.0.0.1','ext-rtp-ip':'127.0.0.1',
          'sip-port':'5060','context':'pdid','dialplan':'XML','rtp-timer-name':'soft',
          'inbound-codec-prefs':'PCMA,PCMU,G729','outbound-codec-prefs':'PCMA,PCMU,G729',
          'auth-calls':'true','apply-inbound-acl':'domains','disable-register':'true',
          'sip-capture':'no','manage-presence':'false'})
local=conf('local_stream.conf')
for name in ['default','moh/8000']:
    directory=E.SubElement(local,'directory',name=name,path='/var/lib/freeswitch/sounds/music/8000')
    for k,v in {'rate':'8000','shuffle':'true','channels':'1','interval':'20','timer-name':'soft'}.items():
        E.SubElement(directory,'param',name=k,value=v)
E.SubElement(conf('ivr.conf'),'menus')
cdr=conf('cdr_csv.conf')
settings(cdr,{'legs':'ab','log-base':'/var/log/freeswitch','default-template':'voip50-local',
             'master-file-only':'true','rotate-on-hup':'false','debug':'false'})
columns=['switch_name','switch_id','switch_ip','uuid','call_uuid','bridge_uuid','signal_bond',
         'direction','context','caller_id_number','destination_number','sip_network_ip','sip_network_port',
         'start_stamp','answer_stamp','end_stamp','duration','billsec','hangup_cause','read_codec','write_codec','accountcode']
values=['voip-50-build','4',ips[0]]+['${'+c+'}' for c in columns[3:]]
E.SubElement(E.SubElement(cdr,'templates'),'template',name='voip50-local').text=','.join('"'+v+'"' for v in values)+'\n'
dialplan=E.SubElement(root,'section',name='dialplan')
scripts={'pdid':'PDIDRoutingReseller.lua','telekomfl':'PDIDRouting.lua','didrouting':'didRouting.lua',
         'routing':'outbound.lua','publicTrunks':'routing.lua','ccdialout':'getCard.lua','ivrs':'playbackOriginalIVR.lua'}
for name,script in scripts.items():
    context=E.SubElement(dialplan,'context',name=name)
    extension=E.SubElement(context,'extension',name='build-hold')
    condition=E.SubElement(extension,'condition',field='${voip50_build_hold}',expression='^true$')
    E.SubElement(condition,'action',application='hangup',data='CALL_REJECTED')
    extension=E.SubElement(context,'extension',name='routing-prepared')
    condition=E.SubElement(extension,'condition',field='destination_number',expression='^(\\d+)$')
    E.SubElement(condition,'action',application='lua',data=script)
domain=E.SubElement(E.SubElement(root,'section',name='directory'),'domain',name=ips[0])
E.SubElement(domain,'users')
E.indent(root)
path=Path('/etc/freeswitch/freeswitch.xml');temp=path.with_suffix('.new')
temp.write_bytes(E.tostring(root,encoding='utf-8'));temp.chmod(0o640)
os.chown(temp,0,grp.getgrnam('freeswitch').gr_gid);temp.replace(path)
Path('/var/log/freeswitch/cdr-csv/columns.json').write_text(json.dumps(columns,indent=2)+'\n')
os.chmod('/var/log/freeswitch/cdr-csv/columns.json',0o640)
os.chown('/var/log/freeswitch/cdr-csv/columns.json',0,grp.getgrnam('freeswitch').gr_gid)
print(json.dumps({'mode':'BUILD','switch_id':4,'management_ip':ips[0],'sip_bind':'127.0.0.1','production_calls_blocked':True}))
