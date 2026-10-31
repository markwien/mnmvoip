#!/usr/bin/python3
"""Exercise the candidate firewall with synthetic packets in isolated network namespaces."""
import base64
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import time
import uuid

ROOT = Path('/root/voip38-build/network-preparation')


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def check():
    spec = importlib.util.spec_from_file_location('candidate', ROOT / 'integrate.candidate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = {'getHostsConfig': (module.STATE / 'current/getHostsConfig').read_bytes()}
    original = json.loads((ROOT / 'production-network-reference.json').read_text())
    zones, _ = module.hosts(payload['getHostsConfig'])
    sets_equal = all({str(ipaddress.ip_network(n, strict=False)) for n in original['public_source_zones'][z]} == zones[z]
                     for z in ['trust', 'voip'])
    assert sets_equal, 'Panel source sets differ from the active old firewall'
    assert ipaddress.ip_address('92.61.63.10') in ipaddress.ip_network('92.61.63.0/24')
    suffix = uuid.uuid4().hex[:6]
    server, wan, lan = ['v38-' + role + '-' + suffix for role in ['s', 'w', 'l']]
    names = [server, wan, lan]
    created = []
    results = []
    sequence = 30000

    def ns(name, args, **kwargs):
        return run(['ip', 'netns', 'exec', name] + args, **kwargs)

    def checksum(data):
        if len(data) % 2:
            data += b'\0'
        total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        return (~total) & 65535

    def frame(client, iface, source, port, protocol, ipv6=False, tcp_flags=2):
        nonlocal sequence
        sequence += 1
        src = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, source)
        dst = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, '2001:db8::38' if ipv6 else '92.61.60.38')
        number = 6 if protocol == 'tcp' else 17
        transport = (struct.pack('!HHLLBBHHH', sequence, port, 1, 0, 0x50, tcp_flags, 4096, 0, 0)
                     if protocol == 'tcp' else struct.pack('!HHHH', sequence, port, 12, 0) + b'LAB!')
        pseudo = src + dst + (struct.pack('!I3xB', len(transport), number) if ipv6 else struct.pack('!BBH', 0, number, len(transport)))
        offset = 16 if protocol == 'tcp' else 6
        transport = transport[:offset] + struct.pack('!H', checksum(pseudo + transport) or 65535) + transport[offset + 2:]
        if ipv6:
            header = struct.pack('!IHBB', 6 << 28, len(transport), number, 64) + src + dst
        else:
            header = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(transport), sequence, 0, 64, number, 0) + src + dst
            header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        server_if = 'testwan0' if client == wan else 'testlan0'
        dst_mac = json.loads(ns(server, ['ip', '-j', 'link', 'show', server_if]).stdout)[0]['address']
        src_mac = json.loads(ns(client, ['ip', '-j', 'link', 'show', iface]).stdout)[0]['address']
        ether = bytes.fromhex(dst_mac.replace(':', '') + src_mac.replace(':', '')) + struct.pack('!H', 0x86dd if ipv6 else 0x0800)
        return ether + header + transport

    def instrument(text):
        text = text.replace('table inet voip38_build {', 'table inet voip38_build {\n counter passed {}\n counter denied {}')
        output = []
        inside = False
        for line in text.splitlines():
            if line.strip() == 'chain input {':
                inside = True
            elif inside and line.strip() == '}':
                output.append('  counter name denied drop')
                inside = False
            if inside and 'policy ' not in line and not line.lstrip().startswith('#'):
                line = line.replace(' accept', ' counter name passed accept').replace(' drop', ' counter name denied drop')
            output.append(line)
        # Count only our marked TCP/UDP probes; autonomous IPv6 control packets are unrelated noise.
        text = '\n'.join(output) + '\n'
        return text.replace('type filter hook input priority 0; policy drop;',
                            'type filter hook input priority 0; policy drop;\n'
                            '  meta l4proto != { tcp, udp } drop\n'
                            '  tcp sport != 30000-40000 drop\n'
                            '  udp sport != 30000-40000 drop')

    def counters():
        data = json.loads(ns(server, ['nft', '-j', 'list', 'table', 'inet', 'voip38_build']).stdout)
        return {v['counter']['name']: v['counter']['packets'] for v in data['nftables'] if 'counter' in v}

    try:
        for name in names:
            run(['ip', 'netns', 'add', name]); created.append(name)
            ns(name, ['ip', 'link', 'set', 'lo', 'up'])
        for client, left, right, target in [(wan, 'v38sw', 'v38cw', 'testwan0'), (lan, 'v38sl', 'v38cl', 'testlan0')]:
            run(['ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
            run(['ip', 'link', 'set', left, 'netns', server])
            run(['ip', 'link', 'set', right, 'netns', client])
            ns(server, ['ip', 'link', 'set', left, 'name', target])
            ns(server, ['ip', 'link', 'set', target, 'up'])
            ns(client, ['ip', 'link', 'set', right, 'up'])
        ns(server, ['ip', 'addr', 'add', '92.61.60.38/26', 'dev', 'testwan0'])
        ns(server, ['ip', 'addr', 'add', '192.168.1.38/24', 'dev', 'testlan0'])
        ns(server, ['ip', '-6', 'addr', 'add', '2001:db8::38/64', 'dev', 'testwan0', 'nodad'])
        for key in ['all', 'default', 'testwan0', 'testlan0']:
            ns(server, ['sysctl', '-q', '-w', 'net.ipv4.conf.' + key + '.rp_filter=0'])
        for mode in ['BUILD', 'LIVE']:
            module.MODE = mode
            # BUILD must see its real management-only topology, while a second port is probed.
            iface = 'testlan0' if mode == 'BUILD' else 'testwan0'
            text, _, _ = module.render_firewall(payload, iface, 'testlan0')
            ns(server, ['nft', '-f', '-'], input=('flush ruleset\n' + instrument(text)).encode())
            tests = []
            for label, source in [('trust', '92.61.63.10'), ('voip', '198.96.222.228'), ('other', '203.0.113.10')]:
                for protocol, ports in [('tcp', [21, 22, 25, 53, 80, 443, 3306, 5029, 5060, 5061, 8021, 8080, 10050]),
                                        ('udp', [53, 67, 68, 5029, 5060, 5061, 9999, 10000, 20000, 60000, 60001])]:
                    for port in ports:
                        allowed = (mode == 'LIVE' and
                                   ((protocol == 'udp' and 10000 <= port <= 60000) or
                                    (label == 'trust' and ((protocol == 'tcp' and port in [21, 22, 80, 3306, 5029, 8021, 8080, 10050]) or
                                                           (protocol == 'udp' and port in [5029, 5060]))) or
                                    (label == 'voip' and ((protocol == 'tcp' and port == 22) or (protocol == 'udp' and port == 5060)))))
                        tests.append((label, source, port, protocol, allowed, wan, 'v38cw', False))
            tests += [('lan', '192.168.1.99', p, proto, True, lan, 'v38cl', False)
                      for p, proto in [(22, 'tcp'), (8021, 'tcp'), (5060, 'udp')]]
            tests += [('ipv6', '2001:db8::99', p, proto, False, wan, 'v38cw', True)
                      for p, proto in [(22, 'tcp'), (8021, 'tcp'), (5060, 'udp'), (20000, 'udp')]]
            tests += [('bad_tcp_flags', '92.61.63.10', 22, 'tcp', False, wan, 'v38cw', False, flags)
                      for flags in [0, 3, 6, 5, 9, 41]]
            for test in tests:
                label, source, port, proto, allowed, client, device, ipv6 = test[:8]
                flags = test[8] if len(test) > 8 else 2
                before = counters()
                packet = frame(client, device, source, port, proto, ipv6, flags)
                ns(client, ['python3', '-c', 'import socket,base64,sys;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((sys.argv[1],0));s.send(base64.b64decode(sys.argv[2]))', device, base64.b64encode(packet).decode()])
                time.sleep(0.01)
                after = counters()
                passed = after['passed'] - before['passed']
                denied = after['denied'] - before['denied']
                success = (passed == 1 and denied == 0) if allowed else (passed == 0 and denied == 1)
                results.append({'mode': mode, 'source_group': label, 'protocol': proto, 'port': port,
                                'expected': 'accept' if allowed else 'drop', 'pass': success,
                                'actual_accept_packets': passed, 'actual_drop_packets': denied})
        value = {'source_sets_match_active_old_firewall': sets_equal, 'isolated_namespaces_only': True,
                 'production_interfaces_used': False, 'tests': len(results), 'passed': sum(r['pass'] for r in results),
                 'all_passed': all(r['pass'] for r in results), 'results': results}
        (ROOT / 'firewall-packet-tests.json').write_text(json.dumps(value, indent=2))
        print(json.dumps({k: v for k, v in value.items() if k != 'results'}))
        assert value['all_passed'], 'One or more isolated firewall packet checks failed'
    finally:
        for name in reversed(created):
            subprocess.run(['ip', 'netns', 'delete', name], capture_output=True)


if __name__ == '__main__':
    check()
