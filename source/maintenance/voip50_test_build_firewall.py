"""Exercise the BUILD rules only inside disposable network namespaces."""
from pathlib import Path
import json
import subprocess
import uuid

suffix=uuid.uuid4().hex[:8]
build='v50b-'+suffix
peer='v50p-'+suffix
created=[]
children=[]
def run(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,**kwargs).stdout.strip()
listener='''import socket,select
tcp=[];udp=[]
for port in [22,443,3306,5060,5061,8021]:
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(8);tcp.append(s)
for port in [68,443,5060]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port));udp.append(s)
print('READY',flush=True)
while True:
 for s in select.select(tcp+udp,[],[],1)[0]:
  if s in tcp:c,a=s.accept();c.close()
  else:b,a=s.recvfrom(100);s.sendto(b,a)
'''
results=[]
try:
    for ns in [build,peer]:
        run(['ip','netns','add',ns]);created.append(ns)
    run(['ip','link','add','vb'+suffix,'type','veth','peer','name','vp'+suffix])
    run(['ip','link','set','vb'+suffix,'netns',build])
    run(['ip','link','set','vp'+suffix,'netns',peer])
    # Match the actual management role used by the additional-NIC quarantine.
    run(['ip','netns','exec',build,'ip','link','set','vb'+suffix,'name','enX0'])
    for ns,link,addr in [(build,'enX0','192.168.1.217/24'),(peer,'vp'+suffix,'192.168.1.216/24')]:
        run(['ip','-n',ns,'addr','add',addr,'dev',link]);run(['ip','-n',ns,'link','set',link,'up']);run(['ip','-n',ns,'link','set','lo','up'])
    run(['ip','-n',peer,'addr','add','198.51.100.10/24','dev','vp'+suffix])
    run(['ip','-n',build,'route','add','198.51.100.0/24','via','192.168.1.216'])
    run(['ip','netns','exec',build,'nft','-f','/etc/nftables.conf'])
    for ns in [build,peer]:
        p=subprocess.Popen(['ip','netns','exec',ns,'python3','-u','-c',listener],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(p);assert p.stdout.readline().strip()=='READY'
    cases=[('LAN SSH',peer,'192.168.1.216',22,'tcp',True),
           ('LAN SIP',peer,'192.168.1.216',5060,'tcp',False),
           ('LAN ESL',peer,'192.168.1.216',8021,'tcp',False),
           ('LAN HTTPS',peer,'192.168.1.216',443,'tcp',False),
           ('non-LAN SSH',peer,'198.51.100.10',22,'tcp',False),
           ('DB egress',build,'192.168.1.217',3306,'tcp',False),
           ('SIP egress',build,'192.168.1.217',5060,'tcp',False),
           ('SIPS egress',build,'192.168.1.217',5061,'tcp',False),
           ('ESL egress',build,'192.168.1.217',8021,'tcp',False),
           ('HTTPS egress',build,'192.168.1.217',443,'tcp',True),
           ('SSH egress',build,'192.168.1.217',22,'tcp',True),
           ('UDP SIP ingress',peer,'192.168.1.216',5060,'udp',False),
           ('UDP SIP egress',build,'192.168.1.217',5060,'udp',False),
           ('UDP HTTPS egress',build,'192.168.1.217',443,'udp',True),
           ('DHCP response',peer,'192.168.1.216',68,'udp-dhcp',True)]
    for label,ns,source,port,proto,expected in cases:
        target='192.168.1.216' if ns==build else '192.168.1.217'
        code='''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if PROTO=='tcp' else socket.SOCK_DGRAM);s.settimeout(.4);s.bind((SOURCE,67 if PROTO=='udp-dhcp' else 0));ok=False
try:
 if PROTO=='tcp':s.connect((TARGET,PORT));ok=True
 else:s.sendto(b'build-fw-check',(TARGET,PORT));ok=s.recvfrom(100)[0]==b'build-fw-check'
except (OSError,socket.timeout):pass
finally:s.close()
print(json.dumps({'connected':ok}))
'''
        prefix='PROTO='+repr(proto)+';SOURCE='+repr(source)+';TARGET='+repr(target)+';PORT='+str(port)+'\n'
        got=json.loads(run(['ip','netns','exec',ns,'python3','-c',prefix+code]))['connected']
        results.append({'case':label,'expected_allowed':expected,'allowed':got,'passed':got==expected})
    assert all(r['passed'] for r in results),'firewall packet expectation failed'
finally:
    for p in children:
        p.terminate()
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    for ns in reversed(created):subprocess.run(['ip','netns','del',ns],capture_output=True)
out={'test_scope':'isolated namespaces inside new BUILD VM; no real network services contacted',
     'cases':results,'passed':sum(r['passed'] for r in results),'total':len(results),'namespaces_removed':True}
p=Path('/root/voip50-build/firewall-verification.json');p.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out))
