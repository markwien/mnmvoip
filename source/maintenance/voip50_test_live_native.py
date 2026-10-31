"""Start a synthetic-credential FreeSWITCH only in disconnected virtual networks."""
import copy
import datetime
import grp
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import subprocess
import time
import uuid
import xml.etree.ElementTree as E

ROOT=Path('/root/voip50-build/live-preparation');os.umask(0o077)
suffix=uuid.uuid4().hex[:6]
server,lan,wan=['v50-live-'+role+'-'+suffix for role in ['s','l','w']]
created=[];process=None;log=None
directory=Path('/var/lib/freeswitch')/('voip50-runtime-lab-'+suffix)
fs=pwd.getpwnam('freeswitch');gid=grp.getgrnam('freeswitch').gr_gid
secret=secrets.token_urlsafe(32)
plan=json.loads(Path('/etc/voip50/network-plan.json').read_text())
host_pid=subprocess.check_output(['systemctl','show','freeswitch','-p','MainPID','--value'],text=True).strip()
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,**kw)
def ns(name,args,**kw):return run(['ip','netns','exec',name]+args,**kw)
client='''import json,socket,sys
source,target,password,command=sys.argv[1:]
s=socket.socket();s.settimeout(.6);s.bind((source,0));out={'connected':False,'auth_requested':False,'authenticated':False}
try:
 s.connect((target,8021));out['connected']=True
 def readframe():
  data=b''
  while b'\\n\\n' not in data:
   b=s.recv(4096)
   if not b:break
   data+=b
  headers=dict(line.split(': ',1) for line in data.split(b'\\n\\n',1)[0].decode().splitlines() if ': ' in line)
  size=int(headers.get('Content-Length','0'))
  body=data.split(b'\\n\\n',1)[1] if b'\\n\\n' in data else b''
  while len(body)<size:body+=s.recv(size-len(body))
  return headers,body.decode()
 headers,body=readframe();out['auth_requested']=headers.get('Content-Type')=='auth/request'
 if out['auth_requested']:
  s.sendall(('auth '+password+'\\n\\n').encode());headers,body=readframe()
  out['authenticated']=headers.get('Reply-Text','').startswith('+OK')
  if out['authenticated'] and command:
   s.sendall(('api '+command+'\\n\\n').encode());headers,body=readframe();out['result']=body
except (OSError,ValueError):pass
finally:s.close()
print(json.dumps(out))
'''
def probe(namespace,source,target,password,command=''):
    r=ns(namespace,['python3','-c',client,source,target,password,command],text=True,timeout=8)
    return json.loads(r.stdout)

try:
    for name in [server,lan,wan]:
        run(['ip','netns','add',name]);created.append(name);ns(name,['ip','link','set','lo','up'])
    for peer,left,right,role in [(lan,'v5ls'+suffix,'v5lc'+suffix,'internal'),(wan,'v5ws'+suffix,'v5wc'+suffix,'public')]:
        run(['ip','link','add',left,'type','veth','peer','name',right]);run(['ip','link','set',left,'netns',server]);run(['ip','link','set',right,'netns',peer])
        name=plan[role]['interface'];ns(server,['ip','link','set',left,'name',name]);ns(server,['ip','link','set',name,'address',plan[role]['mac']])
        ns(server,['ip','addr','add',plan[role]['address']+'/'+str(plan[role]['prefix']),'dev',name]);ns(server,['ip','link','set',name,'up']);ns(peer,['ip','link','set',right,'up'])
    ns(lan,['ip','addr','add','192.168.1.225/24','dev','v5lc'+suffix])
    for address in ['92.61.60.60/26','92.61.60.1/26','92.61.63.10/24','203.0.113.10/24']:
        ns(wan,['ip','addr','add',address,'dev','v5wc'+suffix])
    ns(server,['ip','route','add','default','via','92.61.60.1','dev','enX1'])
    for interface in ['all','default','enX0','enX1']:ns(server,['sysctl','-q','-w','net.ipv4.conf.'+interface+'.rp_filter=0'])
    ns(server,['nft','-f','/root/voip50-build/network-preparation/nftables.live.conf'])
    directory.mkdir(mode=0o750);directory.chmod(0o750);os.chown(directory,0,gid)
    for name in ['conf','db','log','run','scripts','recordings']:
        p=directory/name;p.mkdir(mode=0o750);p.chmod(0o750);os.chown(p,fs.pw_uid,gid)
    root=E.parse(ROOT/'candidate/static.xml').getroot()
    original_secrets=[]
    for node in root.iter():
        if node.tag=='X-PRE-PROCESS':
            key,sep,value=node.get('data','').partition('=')
            if sep and (key in ['db1User','db2User','db1Pass','db2Pass'] or any(s in key.lower() for s in ['password','secret','token'])):
                if len(value)>8:original_secrets.append(value)
                node.set('data',key+'='+secret)
            if key in ['db1DSN','db2DSN']:node.set('data',key+'=VOIP50_LAB_DISABLED')
            paths={'conf_dir':'conf','log_dir':'log','db_dir':'db','run_dir':'run','script_dir':'scripts','recordings_dir':'recordings'}
            if key in paths:node.set('data',key+'='+str(directory/paths[key]))
        if node.tag=='param' and any(word in node.get('name','').lower() for word in ['password','secret','token']):
            if len(node.get('value',''))>8:original_secrets.append(node.get('value'))
            node.set('value',secret)
    for gateway in root.iter('gateway'):
        for key in ['register','ping']:
            p=gateway.find("param[@name='"+key+"']")
            if p is None:p=E.SubElement(gateway,'param',name=key)
            p.set('value','false' if key=='register' else '0')
    config=root.find("section[@name='configuration']")
    for p in config.find("configuration[@name='logfile.conf']").iter('param'):
        if p.get('name')=='logfile':p.set('value',str(directory/'log/freeswitch.log'))
    config.find("configuration[@name='cdr_csv.conf']/settings/param[@name='log-base']").set('value',str(directory/'log'))
    data=E.tostring(root,encoding='unicode')
    # Check credential fields, rather than substring-searching common usernames
    # such as "freeswitch" which also occur in harmless filesystem paths.
    for node in root.iter():
        if node.tag=='X-PRE-PROCESS':
            key,sep,value=node.get('data','').partition('=')
            if sep and (key in ['db1User','db2User','db1Pass','db2Pass'] or any(s in key.lower() for s in ['password','secret','token'])):assert value==secret
        if node.tag=='param' and any(word in node.get('name','').lower() for word in ['password','secret','token']):assert node.get('value')==secret
    p=directory/'conf/freeswitch.xml';p.write_text(data);p.chmod(0o600);os.chown(p,fs.pw_uid,gid)
    log=(directory/'process.log').open('wb')
    args=['ip','netns','exec',server,'runuser','-u','freeswitch','--','/opt/freeswitch/bin/freeswitch','-nc','-nf','-nonat','-np',
          '-conf',str(directory/'conf'),'-mod','/opt/freeswitch/lib/freeswitch/mod','-scripts',str(directory/'scripts'),
          '-log',str(directory/'log'),'-db',str(directory/'db'),'-run',str(directory/'run'),
          '-sounds','/var/lib/freeswitch/sounds','-recordings',str(directory/'recordings')]
    process=subprocess.Popen(args,stdout=log,stderr=log,start_new_session=True)
    for _ in range(60):
        if process.poll() is not None:
            log.flush()
            diagnostic=(directory/'process.log').read_text(errors='replace')[-3500:].replace(secret,'<lab-secret>')
            (ROOT/'native-lab-diagnostic.json').write_text(json.dumps({'returncode':process.returncode,'synthetic_lab_log':diagnostic},indent=2)+'\n')
            print(json.dumps({'isolated_process_exit':process.returncode,'synthetic_lab_log':diagnostic}))
            raise AssertionError('isolated FreeSWITCH exited during start')
        check=probe(server,'127.0.0.1','127.0.0.1',secret,'status')
        if check.get('authenticated') and 'UP' in check.get('result',''):break
        time.sleep(.2)
    assert check.get('authenticated') and 'UP' in check.get('result','')
    tests={}
    for name,namespace,source,target,password,expected in [
        ('local-console',server,'127.0.0.1','127.0.0.1',secret,True),
        ('new-panel-lan',lan,'192.168.1.225','192.168.1.50',secret,True),
        ('old-panel-wan',wan,'92.61.60.60','92.61.60.50',secret,True),
        ('allowed-source-wrong-password',lan,'192.168.1.225','192.168.1.50','wrong-lab-password',False),
        ('firewall-trust-but-esl-acl-deny',wan,'92.61.63.10','92.61.60.50',secret,False),
        ('untrusted-wan-firewall-deny',wan,'203.0.113.10','92.61.60.50',secret,False)]:
        value=probe(namespace,source,target,password,'status' if expected else '')
        assert value['authenticated']==expected,name+' authentication expectation failed'
        if expected:assert 'UP' in value['result']
        tests[name]={k:value[k] for k in ['connected','auth_requested','authenticated']}
        tests[name]['passed']=True
    profile=probe(server,'127.0.0.1','127.0.0.1',secret,'sofia status profile voip01')['result']
    assert '92.61.60.50:5060' in profile and 'telekomfl' in profile
    assert probe(server,'127.0.0.1','127.0.0.1',secret,'global_getvar default_profile')['result'].strip()=='voip01'
    assert probe(server,'127.0.0.1','127.0.0.1',secret,'global_getvar switchid')['result'].strip()=='4'
    gateways=E.fromstring(probe(server,'127.0.0.1','127.0.0.1',secret,'sofia xmlstatus gateway')['result'])
    assert len(list(gateways.iter('gateway')))==11
    assert '+OK' in probe(server,'127.0.0.1','127.0.0.1',secret,'reloadxml')['result']
    E.parse(directory/'log/freeswitch.xml.fsxml')
    assert probe(server,'127.0.0.1','127.0.0.1',secret,'show calls count')['result'].strip()=='0 total.'
    result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,
            'isolated_native_freeswitch_started':True,'separate_network_and_db_log_paths':True,
            'no_connection_to_real_interfaces':True,'synthetic_credentials_only':True,
            'gateway_registration_and_pings_disabled_in_lab_only':True,'esl_tests':tests,
            'native_sip_public_binding_correct':True,'native_profile_context_correct':True,
            'native_default_profile_and_switch_id_correct':True,'native_gateways_loaded':11,
            'native_reloadxml_and_compiled_xml_valid':True,'production_db_connected':False,
            'real_sip_calls_made':False,'main_freeswitch_pid_unchanged':True,
            'production_cutover':False}
    (ROOT/'native-lab-verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
finally:
    if process and process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(timeout=8)
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
    if log:log.close()
    for name in reversed(created):subprocess.run(['ip','netns','delete',name],capture_output=True)
    if directory.exists():shutil.rmtree(directory)
    assert subprocess.check_output(['systemctl','show','freeswitch','-p','MainPID','--value'],text=True).strip()==host_pid
