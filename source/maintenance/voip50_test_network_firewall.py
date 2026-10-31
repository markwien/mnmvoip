"""Packet-test staged LIVE and active BUILD policies in disconnected namespaces."""
import base64
import datetime
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
import uuid

ROOT=Path('/root/voip50-build/network-preparation')
os.umask(0o077)
spec=importlib.util.spec_from_file_location('candidate',ROOT/'voip50_network_candidate.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
zones=module.zones_from_reference()
legacy=json.loads((ROOT/'production-network-reference.json').read_text())['active_filter_chains']
suffix=uuid.uuid4().hex[:6]
server,wan,lan=['v50-'+r+'-'+suffix for r in ['s','w','l']]
created=[];results=[];sequence=30000

def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,**kw)
def ns(name,args,**kw):return run(['ip','netns','exec',name]+args,**kw)
def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def instrument(text):
    text=re.sub(r'chain (input|output|forward) \{ (type filter hook [^}]+) \}',r'chain \1 {\n \2\n }',text)
    output=[];chain=None;drop=False;table=None
    for line in text.splitlines():
        if line.startswith('table inet '):table=line.split()[2]
        match=re.match(r'\s*chain (input|output|forward) \{',line)
        if match:chain=match.group(1);drop=False
        elif chain and line.strip()=='}':
            if drop:output.append('  counter drop comment "v50-test-'+chain+'-drop"')
            elif chain=='output' and table=='voip50_build':output.append('  counter accept comment "v50-test-output-accept"')
            chain=None
        if chain and 'policy ' in line:
            drop='policy drop' in line
            output.append(line)
            output.extend((['  meta l4proto != { tcp, udp } drop'] if chain=='output' else
                           ['  meta nfproto ipv4 ip id != 30000-60000 drop',
                            '  meta nfproto ipv6 meta l4proto != { tcp, udp } drop'])+
                          ['  tcp sport != 30000-60000 drop','  udp sport != 30000-60000 drop'])
            continue
        if chain and 'policy ' not in line and not line.lstrip().startswith('#'):
            line=re.sub(r'\s+comment\s+"[^"]*"','',line)
            for verdict in ['accept','drop','reject']:
                if re.search(r'\s'+verdict+r'$',line):
                    label='accept' if verdict=='accept' else 'drop'
                    line=re.sub(r'\s'+verdict+r'$', ' counter '+verdict+' comment "v50-test-'+chain+'-'+label+'"',line)
        output.append(line)
    return '\n'.join(output)+'\n'

def counters(chain):
    data=json.loads(ns(server,['nft','-j','list','ruleset']).stdout)
    values={'accept':0,'drop':0}
    for entry in data['nftables']:
        rule=entry.get('rule',{})
        for verdict in values:
            if rule.get('comment')=='v50-test-'+chain+'-'+verdict:
                values[verdict]+=sum(e['counter']['packets'] for e in rule['expr'] if 'counter' in e)
    return values

def frame(client,source,port,protocol,ipv6=False,flags=2,destination=None):
    global sequence
    sequence+=1
    family=socket.AF_INET6 if ipv6 else socket.AF_INET
    target=destination or ('2001:db8::50' if ipv6 else '92.61.60.50' if client==wan else '192.168.1.50')
    src=socket.inet_pton(family,source);dst=socket.inet_pton(family,target)
    number={'tcp':6,'udp':17,'icmp':1}[protocol]
    if protocol=='icmp':
        transport=struct.pack('!BBHHH',8,0,0,sequence,1)+b'LAB!'
        transport=transport[:2]+struct.pack('!H',checksum(transport))+transport[4:]
    else:
        transport=(struct.pack('!HHLLBBHHH',sequence,port,1,0,0x50,flags,4096,0,0) if protocol=='tcp'
                   else struct.pack('!HHHH',sequence,port,12,0)+b'LAB!')
        pseudo=src+dst+(struct.pack('!I3xB',len(transport),number) if ipv6 else struct.pack('!BBH',0,number,len(transport)))
        offset=16 if protocol=='tcp' else 6
        transport=transport[:offset]+struct.pack('!H',checksum(pseudo+transport) or 65535)+transport[offset+2:]
    if ipv6:header=struct.pack('!IHBB',6<<28,len(transport),number,64)+src+dst
    else:
        header=struct.pack('!BBHHHBBH',0x45,0,20+len(transport),sequence,0,64,number,0)+src+dst
        header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    server_if='enX1' if client==wan else 'enX0'
    client_if='v5W'+suffix if client==wan else 'v5L'+suffix
    dst_mac=json.loads(ns(server,['ip','-j','link','show',server_if]).stdout)[0]['address']
    src_mac=json.loads(ns(client,['ip','-j','link','show',client_if]).stdout)[0]['address']
    ether=bytes.fromhex(dst_mac.replace(':','')+src_mac.replace(':',''))+struct.pack('!H',0x86dd if ipv6 else 0x0800)
    return client_if,ether+header+transport

def expected_live(source,port,protocol):
    address=ipaddress.ip_address(source)
    trust=any(address in ipaddress.ip_network(n) for n in zones['trust'])
    voip=any(address in ipaddress.ip_network(n) for n in zones['voip'])
    def accepted(rule):
        # Fresh test flows: established/related shortcuts do not apply.
        if not rule.endswith(' -j ACCEPT') or '--ctstate' in rule:return False
        match=re.search(r' -p ([^ ]+)',rule)
        if match and match.group(1)!=protocol:return False
        match=re.search(r' --dport ([^ ]+)',rule)
        if match:
            values=[int(n) for n in match.group(1).split(':')]
            if not values[0]<=port<=values[-1]:return False
        return True
    # Derive expected accepts from the actual old50 iptables rules, independently
    # of the nftables renderer's port definitions.
    if any(accepted(rule) for rule in legacy['eth0_in']):return True
    chain='trust2fw' if trust else 'voip2fw' if voip else 'net2fw'
    return any(accepted(rule) for rule in legacy[chain])

try:
    for name in [server,wan,lan]:
        run(['ip','netns','add',name]);created.append(name);ns(name,['ip','link','set','lo','up'])
    for client,left,right,target in [(wan,'v5w'+suffix,'v5W'+suffix,'enX1'),(lan,'v5l'+suffix,'v5L'+suffix,'enX0')]:
        run(['ip','link','add',left,'type','veth','peer','name',right])
        run(['ip','link','set',left,'netns',server]);run(['ip','link','set',right,'netns',client])
        ns(server,['ip','link','set',left,'name',target]);ns(server,['ip','link','set',target,'up'])
        ns(client,['ip','link','set',right,'up'])
    ns(server,['ip','addr','add','92.61.60.50/26','dev','enX1'])
    ns(server,['ip','addr','add','192.168.1.50/24','dev','enX0'])
    ns(server,['ip','-6','addr','add','2001:db8::50/64','dev','enX1','nodad'])
    ns(wan,['ip','addr','add','92.61.60.2/26','dev','v5W'+suffix])
    ns(lan,['ip','addr','add','192.168.1.99/24','dev','v5L'+suffix])
    for key in ['all','default','enX0','enX1']:ns(server,['sysctl','-q','-w','net.ipv4.conf.'+key+'.rp_filter=0'])
    ns(server,['sysctl','-q','-w','net.ipv4.ip_forward=1'])
    for mode in ['BUILD','LIVE']:
        text=Path('/etc/nftables.conf').read_text() if mode=='BUILD' else module.render_firewall({},'enX1','enX0')[0]
        ns(server,['nft','--check','-f','-'],input=('flush ruleset\n'+text).encode())
        ns(server,['nft','-f','-'],input=('flush ruleset\n'+instrument(text)).encode())
        cases=[]
        for group,source in [('trust','92.61.63.10'),('voip','198.96.222.228'),('other','203.0.113.10')]:
            for protocol,ports in [('tcp',[21,22,25,53,80,443,3306,5029,5060,5061,8021,8080,10050]),
                                   ('udp',[53,67,68,5029,5060,5061,9999,10000,20000,60000,60001])]:
                for port in ports:cases.append((group,source,port,protocol,mode=='LIVE' and expected_live(source,port,protocol),wan,False,2,None,'input'))
            cases.append((group,source,0,'icmp',mode=='LIVE' and group=='trust',wan,False,2,None,'input'))
        if mode=='LIVE':
            for group,networks in zones.items():
                for network in sorted(networks):
                    address=str(ipaddress.ip_network(network).network_address+(1 if ipaddress.ip_network(network).num_addresses>1 else 0))
                    if address=='92.61.60.50':continue
                    for port,protocol in [(22,'tcp'),(8021,'tcp'),(5060,'udp')]:
                        cases.append(('source-list-'+group,address,port,protocol,expected_live(address,port,protocol),wan,False,2,None,'input'))
            for address in ['89.202.102.86','209.160.64.56','81.26.202.53']:
                cases.append(('panel-difference',address,5060,'udp',expected_live(address,5060,'udp'),wan,False,2,None,'input'))
        for port,protocol in [(22,'tcp'),(80,'tcp'),(443,'tcp'),(3306,'tcp'),(8021,'tcp'),(5060,'udp'),(10000,'udp')]:
            cases.append(('lan','192.168.1.99',port,protocol,mode=='LIVE' or (protocol=='tcp' and port==22),lan,False,2,None,'input'))
        cases.append(('lan-ping','192.168.1.99',0,'icmp',True,lan,False,2,None,'input'))
        cases += [('ipv6','2001:db8::99',p,proto,False,wan,True,2,None,'input') for p,proto in [(22,'tcp'),(8021,'tcp'),(5060,'udp'),(20000,'udp')]]
        cases += [('bad-tcp-flags','92.61.63.10',22,'tcp',False,wan,False,f,None,'input') for f in [0,3,6,5,9,41]]
        cases += [('lan-source-on-wan','192.168.1.99',22,'tcp',False,wan,False,2,None,'input'),
                  ('forwarding','203.0.113.10',5060,'udp',False,wan,False,2,'192.168.1.99','forward')]
        for group,source,port,protocol,allowed,client,ipv6,flags,destination,chain in cases:
            before=counters(chain);device,packet=frame(client,source,port,protocol,ipv6,flags,destination)
            ns(client,['python3','-c','import socket,base64,sys;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((sys.argv[1],0));s.send(base64.b64decode(sys.argv[2]))',device,base64.b64encode(packet).decode()])
            after=counters(chain);accepted=after['accept']-before['accept'];denied=after['drop']-before['drop']
            success=(accepted==1 and denied==0) if allowed else (accepted==0 and denied==1)
            results.append({'mode':mode,'direction':chain,'source_group':group,'protocol':protocol,'port':port,'expected':'accept' if allowed else 'drop','pass':success,'accept_packets':accepted,'drop_packets':denied})
        for group,source,target,port,protocol,allowed in [('wan','92.61.60.50','92.61.60.2',443,'udp',mode=='LIVE'),('wan-db','92.61.60.50','92.61.60.2',3306,'tcp',mode=='LIVE'),('lan','192.168.1.50','192.168.1.99',443,'udp',True),('lan-db','192.168.1.50','192.168.1.99',3306,'tcp',mode=='LIVE'),('lan-sip','192.168.1.50','192.168.1.99',5060,'udp',mode=='LIVE'),('lan-sips','192.168.1.50','192.168.1.99',5061,'tcp',mode=='LIVE'),('lan-esl','192.168.1.50','192.168.1.99',8021,'tcp',mode=='LIVE')]:
            sequence+=1;before=counters('output')
            code='import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if sys.argv[5]=="tcp" else socket.SOCK_DGRAM);s.settimeout(.1);s.bind((sys.argv[1],int(sys.argv[3])));\ntry:\n if sys.argv[5]=="tcp":s.connect((sys.argv[2],int(sys.argv[4])))\n else:s.sendto(b"LAB!",(sys.argv[2],int(sys.argv[4])))\nexcept OSError:pass'
            ns(server,['python3','-c',code,source,target,str(sequence),str(port),protocol])
            after=counters('output');accepted=after['accept']-before['accept'];denied=after['drop']-before['drop']
            results.append({'mode':mode,'direction':'output','source_group':group,'protocol':protocol,'port':port,'expected':'accept' if allowed else 'drop','pass':(accepted==1 and denied==0) if allowed else (accepted==0 and denied==1),'accept_packets':accepted,'drop_packets':denied})
    value={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'isolated_namespaces_only':True,
           'production_interfaces_used':False,'real_public_ips_not_assigned_on_host':True,
           'tests':len(results),'passed':sum(r['pass'] for r in results),'all_passed':all(r['pass'] for r in results),
           'live_source_zone_counts':{k:len(v) for k,v in zones.items()},'results':results}
    (ROOT/'firewall-packet-tests.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({k:v for k,v in value.items() if k!='results'}))
    if not value['all_passed']:print(json.dumps({'failures':[r for r in results if not r['pass']]}))
    assert value['all_passed'],'isolated firewall packet expectation failed'
finally:
    for name in reversed(created):subprocess.run(['ip','netns','delete',name],capture_output=True)
