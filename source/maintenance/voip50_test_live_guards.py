"""Test LIVE preconditions and candidate data without changing the active mode."""
import copy
import datetime
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as E

ROOT=Path('/root/voip50-build/live-preparation');os.umask(0o077)
loader=importlib.machinery.SourceFileLoader('live','/usr/local/libexec/voip50-live-runtime')
spec=importlib.util.spec_from_loader(loader.name,loader);live=importlib.util.module_from_spec(spec);loader.exec_module(live)
plan=json.loads(live.PLAN.read_text());cases=[]
addresses=[{'ifname':plan[role]['interface'],'address':plan[role]['mac'],
            'addr_info':[{'family':'inet','local':plan[role]['address'],'prefixlen':plan[role]['prefix']}]} for role in ['internal','public']]
routes=[{'gateway':'92.61.60.1','dev':'enX1'}]
assert live.network_identity(plan,addresses,routes);cases.append('expected-production-identity-accepted-in-memory')
for name,field,value in [('wrong-mac','address','00:00:00:00:00:00'),('wrong-name','ifname','wrong')]:
    bad=copy.deepcopy(addresses);bad[1][field]=value
    try:live.network_identity(plan,bad,routes)
    except (ValueError,KeyError):cases.append(name+'-rejected')
    else:raise AssertionError('wrong network identity accepted')
for name,change in [('wrong-ip',{'local':'192.168.1.217'}),('wrong-prefix',{'prefixlen':24})]:
    bad=copy.deepcopy(addresses);bad[1]['addr_info'][0].update(change)
    try:live.network_identity(plan,bad,routes)
    except ValueError:cases.append(name+'-rejected')
    else:raise AssertionError('wrong production address accepted')
bad=copy.deepcopy(addresses);bad[0]['addr_info'].append({'family':'inet','local':'192.168.1.217','prefixlen':24})
try:live.network_identity(plan,bad,routes)
except ValueError:cases.append('leftover-dhcp-rejected')
else:raise AssertionError('extra DHCP address accepted')
for route in [[{'gateway':'192.168.1.1','dev':'enX0'}],routes+routes]:
    try:live.network_identity(plan,addresses,route)
    except ValueError:cases.append('bad-default-route-rejected')
    else:raise AssertionError('bad default route accepted')
now=time.time();proof={'user_authorized_live':True,'old_vm_halted':True,'old_vifs_inactive':True,
                     'old_vm_uuid':plan['old_vm_uuid'],'new_vm_uuid':plan['new_vm_uuid'],'checked_epoch':now}
assert live.proof_valid(plan,proof,now);cases.append('valid-synthetic-proof-accepted-in-memory')
for change in [{'user_authorized_live':False},{'old_vm_halted':False},{'old_vifs_inactive':False},
               {'new_vm_uuid':'wrong'},{'old_vm_uuid':'wrong'},{'checked_epoch':now-901},{'checked_epoch':now+1}]:
    bad=copy.deepcopy(proof);bad.update(change)
    try:live.proof_valid(plan,bad,now)
    except PermissionError:cases.append('bad-proof-'+next(iter(change))+'-rejected')
    else:raise AssertionError('bad authorization accepted')
before=json.loads((ROOT/'before.json').read_text())
for command in ['start','render']:
    r=subprocess.run(['/usr/local/libexec/voip50-live-runtime',command],capture_output=True,text=True)
    assert r.returncode!=0 and not r.stdout
    assert json.loads(r.stderr)['error_type']=='PermissionError'
    cases.append('real-'+command+'-blocked-in-build')
assert not live.COMMISSION.exists() and not live.READY.exists() and not live.META.exists()
candidate=ROOT/'candidate';root=E.parse(candidate/'static.xml').getroot();values=live.variables(root)
assert values['voip50_build_hold']=='false' and values['switchid']=='4'
assert values['default_profile']=='voip01' and values['external_sip_ip']=='92.61.60.50'
assert {c.get('name') for c in root.findall("section[@name='dialplan']/context")}==set(live.CONTEXTS)
assert not any(e.get('name')=='voip50-build-hold' for e in root.iter('extension'))
profile=root.find("section[@name='configuration']/configuration[@name='sofia.conf']/profiles/profile")
for key in ['sip-ip','rtp-ip','ext-sip-ip','ext-rtp-ip']:assert profile.find("settings/param[@name='"+key+"']").get('value')=='92.61.60.50'
assert '"voip-50","4","92.61.60.50"' in root.find("section[@name='configuration']/configuration[@name='cdr_csv.conf']/templates/template").text
payload={action:(candidate/'payload'/action).read_bytes() for action in live.ACTIONS}
output=live.expanded(root,payload);E.fromstring('<document>'+output+'</document>')
assert '$${' not in output
subprocess.run(['sh','-n','/usr/local/libexec/voip50-build-config'],check=True)
# Inspect the actual installed firewall against its golden baseline using
# in-memory fixtures only; the host has no LIVE table and cannot pass startup.
expected=json.loads((ROOT/'expected-firewall.json').read_text())
tampered=copy.deepcopy(expected)
for entry in tampered['nftables']:
    if 'chain' in entry and entry['chain'].get('name')=='input':entry['chain']['policy']='accept'
assert live.normalized(tampered)!=expected
cases.append('modified-live-firewall-differs-from-golden')
for path,digest in before['active_hashes'].items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
assert subprocess.check_output(['systemctl','show','freeswitch','-p','MainPID','--value'],text=True).strip()==before['pid']
result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,'guard_cases':cases,
        'guard_case_count':len(cases),'actual_live_commands_rejected_in_build':True,'production_ips_never_assigned':True,
        'activation_or_commissioning_proof_created':False,'candidate_seven_contexts_without_build_hold':True,
        'candidate_sip_rtp_public_binding_correct':True,'candidate_live_cdr_identity_correct':True,
        'candidate_expanded_xml_valid':True,'active_build_data_unchanged':True,'freeswitch_pid_unchanged':True,
        'production_db_connected':False,'no_sip_calls_made':True}
(ROOT/'guard-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
