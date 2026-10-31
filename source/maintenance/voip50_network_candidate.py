"""Render an inactive two-interface firewall from the old 50er's active policy."""
import ipaddress
import json
from pathlib import Path
import re

ROOT=Path('/root/voip50-build/network-preparation')
MODE='LIVE'

def zones_from_reference():
    reference=json.loads((ROOT/'production-network-reference.json').read_text())
    zones={name:set() for name in ['trust','voip']}
    for line in reference['active_filter_chains']['eth0_in']:
        match=re.search(r' -s ([^ ]+) -j (trust|voip)2fw$',line)
        if match:zones[match.group(2)].add(str(ipaddress.ip_network(match.group(1),strict=False)))
    assert all(zones.values())
    return zones

def hosts(data):
    zones={name:set() for name in ['trust','voip']};count=0
    for line in data.decode().splitlines():
        f=line.split('#',1)[0].split()
        if not f:continue
        if len(f)!=2 or f[0] not in zones or not f[1].startswith('eth0:'):raise ValueError('invalid source list')
        for net in f[1].split(':',1)[1].split(','):
            network=ipaddress.ip_network(net,strict=False)
            if network.version!=4 or network.prefixlen==0:raise ValueError('invalid source range')
            zones[f[0]].add(str(network))
        count+=1
    assert all(zones.values())
    return zones,count

def render_firewall(payload,interface,lan_interface):
    if MODE!='LIVE' or interface==lan_interface:raise ValueError('distinct LIVE interface roles required')
    if not all(re.fullmatch(r'[a-zA-Z0-9_.-]+',s) for s in [interface,lan_interface]):raise ValueError('invalid interface')
    zones=zones_from_reference()
    # Inactive artifact only: no apply function and no timer in this module.
    # The source lists are pinned to active old50 rules, not the divergent panel list.
    text='''# INACTIVE: old VoIP50 policy mapped to the two prepared interfaces.
# Do not load on the active BUILD host. No forwarding/NAT, no IPv6 exposure.
table inet voip50_live {
 set trust4 { type ipv4_addr; flags interval; auto-merge; elements = { TRUST } }
 set voip4 { type ipv4_addr; flags interval; auto-merge; elements = { VOIP } }
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
  iifname != { "WAN", "LAN" } drop
  meta nfproto ipv6 drop
  ip saddr 224.0.0.0/4 drop
  ip saddr != 0.0.0.0 fib saddr type broadcast drop
  tcp flags & (fin | syn | rst | psh | ack | urg) == (fin | psh | urg) drop
  tcp flags & (fin | syn | rst | psh | ack | urg) == 0 drop
  tcp flags & (syn | rst) == (syn | rst) drop
  tcp flags & (fin | rst) == (fin | rst) drop
  tcp flags & (fin | syn) == (fin | syn) drop
  tcp flags & (fin | psh | ack) == (fin | psh) drop
  tcp sport 0 tcp flags & (fin | syn | rst | ack) == syn drop
  ct state invalid drop
  ct state established,related accept
  iifname "LAN" accept comment "old50 loc policy"
  iifname "WAN" udp dport { 67, 68 } accept comment "old50 DHCP interface option"
  iifname "WAN" ip saddr @trust4 tcp dport { 21, 22, 80, 3306, 5029, 8021, 8080, 10050 } accept
  iifname "WAN" ip saddr @trust4 udp dport { 5029, 5060 } accept
  iifname "WAN" ip saddr @trust4 meta l4proto icmp accept
  iifname "WAN" ip saddr @voip4 tcp dport 22 accept
  iifname "WAN" ip saddr @voip4 udp dport 5060 accept
  iifname "WAN" udp dport 10000-60000 accept comment "old50 RTP, including third-party media"
  iifname "WAN" icmp type destination-unreachable icmp code frag-needed accept
  iifname "WAN" icmp type time-exceeded accept
 }
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  meta nfproto ipv4 oifname { "WAN", "LAN" } accept comment "old50 fw to net and loc"
 }
 chain forward { type filter hook forward priority 0; policy drop; }
}
'''.replace('TRUST',', '.join(sorted(zones['trust']))).replace('VOIP',', '.join(sorted(zones['voip']))).replace('WAN',interface).replace('LAN',lan_interface)
    return text,sum(len(s) for s in zones.values()),{k:len(v) for k,v in zones.items()}

if __name__=='__main__':
    plan=json.loads((ROOT/'network-plan.json').read_text())
    text,_,counts=render_firewall({},plan['public']['interface'],plan['internal']['interface'])
    target=ROOT/'nftables.live.conf';target.write_text(text);target.chmod(0o600)
    print(json.dumps({'candidate_written':True,'applied':False,'zones':counts}))
