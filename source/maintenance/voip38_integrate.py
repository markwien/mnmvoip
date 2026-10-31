#!/usr/bin/python3
"""Staged VoIP38 integration. BUILD is the default; LIVE needs explicit operator approval and both final interfaces."""
import copy
import datetime
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

BASE = Path('/root/voip38-build')
REF = BASE / 'production-reference/etc/freeswitch'
STATE = BASE / 'integration'
ACTIONS = ['getHostsConfig', 'getGateways', 'getGatewayUsers', 'getCardsConfig', 'ivrXML']
MODE_FILE = Path('/etc/voip38/mode')
MODE = 'BUILD'


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def atomic(path, data, mode=0o600, fs_group=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.new')
    temp.write_bytes(data if isinstance(data, bytes) else data.encode())
    temp.chmod(mode)
    if fs_group:
        os.chown(temp, 0, grp.getgrnam('freeswitch').gr_gid)
    temp.replace(path)


def xml_fragment(data):
    text = re.sub(r'<\?xml[^>]*\?>', '', data.decode())
    if '<html' in text.lower() or '<!doctype' in text.lower():
        raise ValueError('HTML received instead of configuration')
    return ET.fromstring('<reference>' + text + '</reference>')


def hosts(data):
    result = {'trust': set(), 'voip': set()}
    count = 0
    for line in data.decode().splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        if len(fields) != 2 or fields[0] not in result:
            raise ValueError('unexpected firewall zone or columns')
        interface, addresses = fields[1].split(':', 1)
        if interface != 'eth0':
            raise ValueError('unexpected production interface')
        for value in addresses.split(','):
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError('unexpected address family')
            result[fields[0]].add(str(network))
        count += 1
    if not count or not result['voip']:
        raise ValueError('empty firewall configuration')
    return result, count


def validate(payload):
    hosts(payload['getHostsConfig'])
    for name in ACTIONS[1:]:
        root = xml_fragment(payload[name])
        expected = {'getGateways': 'gateway', 'getGatewayUsers': 'user', 'getCardsConfig': 'user', 'ivrXML': 'menu'}[name]
        if name != 'getCardsConfig' and not list(root.iter(expected)):
            raise ValueError('empty required XML section')
    # Explicitly reject any unexpected executable preprocessor content from the HTTP payload.
    for name in ACTIONS[1:]:
        if list(xml_fragment(payload[name]).iter('X-PRE-PROCESS')):
            raise ValueError('unexpected remote preprocessor command')


def fetch(firewall_only=False):
    text = (BASE / 'production-reference/etc/shorewall/reloadConfig.sh').read_text()
    url = re.findall(r'https?://[^\s\x22\x27]+', text)[0]
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    switch_id = query['switchid'][0]
    if not switch_id.isdigit():
        raise ValueError('invalid source switch identity')
    payload = ({name: (STATE / 'current' / name).read_bytes() for name in ACTIONS}
               if firewall_only else {})
    for action in (['getHostsConfig'] if firewall_only else ACTIONS):
        suffix = '?' + urllib.parse.urlencode({'switchid': switch_id}) if action != 'ivrXML' else ''
        origin = 'http://192.168.1.60' if MODE == 'BUILD' else 'https://www.telemediacloud.com'
        host = 'config.telemediacloud.com' if MODE == 'BUILD' else 'www.telemediacloud.com'
        request = urllib.request.Request(origin + '/configHandler/' + action + suffix,
                                         headers={'Host': host})
        with urllib.request.urlopen(request, timeout=12) as response:
            data = response.read(8 * 1024 * 1024)
            if response.status != 200 or len(data) >= 8 * 1024 * 1024:
                raise ValueError('invalid HTTP response')
            payload[action] = data
    validate(payload)
    return payload


def network_address():
    route = json.loads(run(['ip', '-j', 'route', 'get', '1.1.1.1']).stdout)[0]
    address = str(ipaddress.IPv4Address(route['prefsrc']))
    if MODE == 'BUILD' and ipaddress.IPv4Address(address) not in ipaddress.IPv4Network('192.168.1.0/24'):
        raise ValueError('BUILD requires the existing DHCP management LAN; production IP activation is separate')
    interface = route['dev']
    if not re.fullmatch(r'[a-zA-Z0-9_.-]+', interface):
        raise ValueError('invalid interface')
    lan_interface = interface
    if MODE == 'LIVE':
        # `ip -4 addr` omits link-layer MAC fields; retain them and filter address families below.
        addresses = json.loads(run(['ip', '-j', 'addr', 'show']).stdout)
        owners = {a['local']: item['ifname'] for item in addresses for a in item.get('addr_info', [])}
        if address != '92.61.60.38' or owners.get('92.61.60.38') != interface or '192.168.1.38' not in owners:
            raise ValueError('LIVE requires the original public and internal addresses and public default route')
        lan_interface = owners['192.168.1.38']
        if lan_interface == interface:
            raise ValueError('LIVE requires distinct internal and public interfaces, as on the 38er')
        plan_path = Path('/etc/voip38/network-plan.json')
        info = plan_path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('network plan must be root-owned and protected')
        plan = json.loads(plan_path.read_text())
        by_name = {item['ifname']: item for item in addresses}
        for role, actual in [('public', interface), ('internal', lan_interface)]:
            expected = plan[role]
            item = by_name[actual]
            if item.get('address', '').lower() != expected['mac'].lower():
                raise ValueError('LIVE interface MAC does not match its prepared network role')
            ipv4 = {(a['local'], a['prefixlen']) for a in item.get('addr_info', [])
                    if a.get('family', 'inet') == 'inet'}
            if ipv4 != {(expected['address'], expected['prefix'])}:
                raise ValueError('LIVE requires exactly the prepared IPv4 address and prefix per interface')
        if route.get('gateway') != plan['public']['gateway']:
            raise ValueError('LIVE default gateway differs from the original 38er')
    return address, interface, lan_interface


def param(parent, name, value):
    node = next((n for n in parent.findall('param') if n.get('name') == name), None)
    if node is None:
        node = ET.SubElement(parent, 'param', name=name)
    node.set('value', value)


def render_xml(payload, address):
    root = ET.parse(BASE / 'candidate/freeswitch.xml').getroot()
    configuration = root.find("section[@name='configuration']")
    # Configuration globals required by Lua are retained; no script runs during this build.
    for node in root.findall('X-PRE-PROCESS'):
        name, _, value = node.get('data', '').partition('=')
        if name in ['domain', 'external_sip_ip', 'external_rtp_ip', 'local_ip_v4']:
            node.set('data', name + '=' + address)
    hold = MODE == 'BUILD'
    root.insert(0, ET.Element('X-PRE-PROCESS', cmd='set', data='voip38_build_hold=' + str(hold).lower()))
    root.insert(0, ET.Element('X-PRE-PROCESS', cmd='set',
                              data='sound_prefix=/var/lib/freeswitch/sounds/en/us/callie'))
    for conf in configuration.findall('configuration'):
        if conf.get('name') == 'modules.conf':
            modules = conf.find('modules')
            for node in list(modules):
                if node.get('module') == 'mod_g729':
                    modules.remove(node)  # Use the real bcg729 codec, as on the 38er, not a second passthrough registration.
            for name in ['mod_native_file', 'mod_local_stream', 'mod_say_en']:
                if not any(m.get('module') == name for m in modules):
                    ET.SubElement(modules, 'load', module=name)
        if conf.get('name') == 'switch.conf':
            param(conf.find('settings'), 'loglevel', 'notice')
        if conf.get('name') == 'logfile.conf':
            for mappings in conf.iter('mappings'):
                for node in mappings:
                    node.tag = 'map'
                    if node.get('name') == 'all':
                        node.set('value', 'warning,err,crit,alert')
        if conf.get('name') == 'sofia.conf':
            # Preserve the existing HOMER destination without enabling SIP capture.
            original_sofia = ET.parse(REF / 'autoload_configs/sofia.conf.xml')
            for item in original_sofia.iter('param'):
                if item.get('name') == 'capture-server':
                    global_settings = conf.find('global_settings')
                    if global_settings is None:
                        global_settings = ET.SubElement(conf, 'global_settings')
                    param(global_settings, 'capture-server', item.get('value'))
            for profile in conf.iter('profile'):
                settings = profile.find('settings')
                for name in ['sip-ip', 'rtp-ip', 'ext-sip-ip', 'ext-rtp-ip']:
                    param(settings, name, address)
                param(settings, 'rtp-timer-name', 'soft')
                if hold:
                    param(settings, 'disable-register', 'true')
                else:
                    for item in list(settings):
                        if item.get('name') == 'disable-register':
                            settings.remove(item)
                    for item in ET.parse(REF / 'sip_profiles/voip01.xml').iter('param'):
                        if item.get('name') == 'disable-register':
                            param(settings, 'disable-register', item.get('value'))
                for node in list(settings):
                    if node.get('name') in ['odbc-dsn', 'core-db-dsn']:
                        settings.remove(node)
                gateways = profile.find('gateways')
                if gateways is None:
                    gateways = ET.SubElement(profile, 'gateways')
                gateways.clear()
                for gateway in xml_fragment(payload['getGateways']):
                    gateway = copy.deepcopy(gateway)
                    if hold:
                        param(gateway, 'register', 'false')
                        param(gateway, 'ping', '0')
                    gateways.append(gateway)
        if conf.get('name') == 'event_socket.conf':
            # Preserve the 38er's panel credential and ACL, including after the future IP move.
            current = ET.parse(REF / 'autoload_configs/event_socket.conf.xml')
            source = next(c for c in current.iter('configuration') if c.get('name') == 'event_socket.conf')
            conf.clear()
            conf.attrib.update(source.attrib)
            for child in source:
                conf.append(copy.deepcopy(child))
            settings = conf.find('settings')
            param(settings, 'listen-ip', '0.0.0.0')
            param(settings, 'listen-port', '8021')
            param(settings, 'apply-inbound-acl', 'esl')
            param(settings, 'nat-map', 'false')
        if conf.get('name') == 'acl.conf':
            lists = conf.find('network-lists')
            domains = next(n for n in lists.findall('list') if n.get('name') == 'domains')
            # Keep the domain-driven ACL and add only self/loopback for the local tone proof.
            for cidr in ['127.0.0.1/32', address + '/32']:
                ET.SubElement(domains, 'node', type='allow', cidr=cidr)
    old_ivr = next((c for c in configuration if c.get('name') == 'ivr.conf'), None)
    if old_ivr is not None:
        configuration.remove(old_ivr)
    ivr = ET.SubElement(configuration, 'configuration', name='ivr.conf', description='Panel IVR reference')
    menus = ET.SubElement(ivr, 'menus')
    for menu in xml_fragment(payload['ivrXML']).iter('menu'):
        menus.append(copy.deepcopy(menu))
    local_stream = ET.SubElement(configuration, 'configuration', name='local_stream.conf', description='Standard hold music')
    for name in ['default', 'moh/8000']:
        directory_node = ET.SubElement(local_stream, 'directory', name=name, path='/var/lib/freeswitch/sounds/music/8000')
        for key, value in {'rate': '8000', 'shuffle': 'true', 'channels': '1', 'interval': '20', 'timer-name': 'soft'}.items():
            param(directory_node, key, value)
    dialplan = root.find("section[@name='dialplan']")
    dialplan.clear()
    dialplan.set('name', 'dialplan')
    contexts = []
    for source in sorted((REF / 'dialplan').glob('*.xml')):
        for context in ET.parse(source).iter('context'):
            context = copy.deepcopy(context)
            contexts.append(context.get('name'))
            # No production Lua, accounting hooks or real bridges are reachable in BUILD.
            tone = ET.Element('extension', name='build-local-audio-proof')
            condition = ET.SubElement(tone, 'condition', field='${network_addr}:${destination_number}',
                                      expression=r'^(127\.0\.0\.1|' + re.escape(address) + r'):9198$')
            for app, data in [('answer', ''), ('playback', 'tone_stream://%(10000,0,440)'), ('hangup', 'NORMAL_CLEARING')]:
                ET.SubElement(condition, 'action', application=app, data=data)
            hold_extension = ET.Element('extension', name='build-reject-production-calls')
            condition = ET.SubElement(hold_extension, 'condition', field='destination_number', expression='^.*$')
            ET.SubElement(condition, 'action', application='hangup', data='CALL_REJECTED')
            if MODE == 'BUILD':
                context.insert(0, hold_extension)
                context.insert(0, tone)
            dialplan.append(context)
    directory = root.find("section[@name='directory']")
    domain = directory.find('domain')
    if domain is None:
        raise ValueError('missing configured domain')
    for node in list(domain):
        if node.tag in ['users', 'groups']:
            domain.remove(node)
    users = ET.SubElement(domain, 'users')
    for name in ['getGatewayUsers', 'getCardsConfig']:
        for user in xml_fragment(payload[name]).iter('user'):
            users.append(copy.deepcopy(user))
    ET.indent(root)
    return ET.tostring(root, encoding='utf-8'), contexts


def render_firewall(payload, interface, lan_interface):
    zones, count = hosts(payload['getHostsConfig'])
    def elements(name):
        return ', '.join(sorted(zones[name]))
    if MODE == 'LIVE' and interface == lan_interface:
        raise ValueError('LIVE firewall requires separate public and internal interfaces')
    build = MODE == 'BUILD'
    ingress_guard = (f'  iifname != "{lan_interface}" drop comment "BUILD accepts only management interface"\n'
                     if build else
                     f'  iifname != {{ "{interface}", "{lan_interface}" }} drop\n')
    management = (f'  iifname "{lan_interface}" udp sport 67 udp dport 68 accept\n'
                  f'  iifname "{lan_interface}" tcp dport 22 accept comment "BUILD LAN recovery only"\n'
                  f'  iifname "{lan_interface}" ip saddr 192.168.1.0/24 accept comment "38er loc management LAN"\n'
                  if build else
                  f'  iifname "{lan_interface}" accept comment "original 38er loc policy"\n')
    egress_guard = (f'  oifname != "{lan_interface}" reject comment "BUILD has no public egress"\n'
                    if build else '')
    egress_hold = ('''  tcp dport { 3306, 8021, 5060, 5061 } reject
  udp dport { 5060, 5061 } reject
''' if build else '')
    text = '''# Managed on this replacement VM only. MODE firewall; default deny on input and forward.
table inet voip38_build {
 set trust4 { type ipv4_addr; flags interval; auto-merge; elements = { TRUST } }
 set voip4 { type ipv4_addr; flags interval; auto-merge; elements = { VOIP } }
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
INGRESS_GUARD
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
MANAGEMENT
  iifname "IFACE" ip saddr @trust4 tcp dport { 21, 22, 80, 3306, 5029, 8021, 8080, 10050 } accept
  iifname "IFACE" ip saddr @trust4 udp dport { 5029, 5060 } accept
  iifname "IFACE" ip saddr @trust4 meta l4proto icmp accept
  iifname "IFACE" ip saddr @voip4 tcp dport 22 accept
  iifname "IFACE" ip saddr @voip4 udp dport 5060 accept
  # Same media allowance as the 38er: RTP can originate outside the signaling IP set.
  iifname "IFACE" meta nfproto ipv4 udp dport 10000-60000 accept
  # Shorewall Drop/Reject also permits PMTU and time-exceeded errors.
  iifname "IFACE" icmp type destination-unreachable icmp code frag-needed accept
  iifname "IFACE" icmp type time-exceeded accept
 }
 chain output {
  type filter hook output priority 0; policy accept;
  oifname "lo" accept
EGRESS_GUARD
  ct state established,related accept
EGRESS_HOLD
 }
 chain forward { type filter hook forward priority 0; policy drop; }
}
'''.replace('INGRESS_GUARD\n', ingress_guard).replace('MANAGEMENT\n', management).replace('EGRESS_GUARD\n', egress_guard).replace('EGRESS_HOLD\n', egress_hold).replace('MODE', MODE).replace('TRUST', elements('trust')).replace('VOIP', elements('voip')).replace('IFACE', interface)
    return text, count, {n: len(v) for n, v in zones.items()}


def apply_firewall(text):
    present = subprocess.run(['nft', 'list', 'table', 'inet', 'voip38_build'], capture_output=True).returncode == 0
    batch = ('delete table inet voip38_build\n' if present else '') + text
    run(['nft', '-c', '-f', '-'], input=batch.encode())
    run(['nft', '-f', '-'], input=batch.encode())
    atomic('/etc/nftables.conf', text, 0o644)


def deploy_scripts():
    target = Path('/var/lib/freeswitch/scripts')
    for source in (BASE / 'candidate/scripts').glob('*.lua'):
        text = source.read_text()
        if source.name == 'dbconnect.lua':
            text = re.sub(r'^.*consoleLog\(.*and password.*\n', '', text, flags=re.M)
            text = text.replace('function connectDB()', '''function connectDB()
    if freeswitch.getGlobalVariable("voip38_build_hold") == "true" then
        freeswitch.consoleLog("warning", "Database routing is disabled during BUILD mode\\n")
        return nil
    end''', 1)
        atomic(target / source.name, text, 0o640, True)
    atomic('/etc/odbc.ini', (BASE / 'candidate/odbc.ini').read_bytes(), 0o640, True)


def master_document(template):
    source = ET.fromstring(template)
    root = ET.Element('document', type='freeswitch/xml')
    for node in source.findall('X-PRE-PROCESS'):
        root.append(copy.deepcopy(node))
    ET.SubElement(root, 'X-PRE-PROCESS', cmd='exec', data='/usr/local/libexec/voip38-render-xml')
    ET.indent(root)
    return ET.tostring(root, encoding='utf-8')


def seed_native_cache(payload):
    cache = Path('/var/lib/freeswitch/xml-cache')
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    user = __import__('pwd').getpwnam('freeswitch')
    os.chown(cache, user.pw_uid, user.pw_gid)
    cache.chmod(0o700)
    generation = cache / ('generation-' + uuid.uuid4().hex)
    generation.mkdir(mode=0o700)
    os.chown(generation, user.pw_uid, user.pw_gid)
    for name in ACTIONS[1:]:
        target = generation / name
        atomic(target, payload[name])
        os.chown(target, user.pw_uid, user.pw_gid)
    link = cache / 'current.new'
    link.unlink(missing_ok=True)
    link.symlink_to(generation)
    link.replace(cache / 'current')


def main():
    global MODE
    os.umask(0o077)
    if not MODE_FILE.exists():
        atomic(MODE_FILE, 'BUILD\n')
    if MODE_FILE.stat().st_uid != 0 or MODE_FILE.stat().st_mode & 0o022:
        raise ValueError('mode control must be root-owned and not writable by others')
    MODE = MODE_FILE.read_text().strip()
    if MODE not in ['BUILD', 'LIVE']:
        raise ValueError('unknown operating mode')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (STATE / 'sync.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    command = sys.argv[1] if len(sys.argv) > 1 else 'sync'
    address, interface, lan_interface = network_address()
    old = STATE / 'current'
    source = 'panel'
    try:
        payload = fetch(command == 'sync')
    except Exception as error:
        if command != 'start' or not old.exists():
            atomic(STATE / 'last-error.json', json.dumps({'error_type': type(error).__name__, 'previous_generation_retained': old.exists()}))
            raise SystemExit('Panel validation failed; current configuration retained')
        payload = {name: (old / name).read_bytes() for name in ACTIONS}
        validate(payload)
        source = 'last-known-good'
    template, contexts = render_xml(payload, address)
    xml = master_document(template)
    firewall, count, counts = render_firewall(payload, interface, lan_interface)
    generation = STATE / ('generation-' + uuid.uuid4().hex)
    generation.mkdir(mode=0o700)
    for name, data in payload.items():
        atomic(generation / name, data)
    atomic(generation / 'freeswitch.xml', xml)
    atomic(generation / 'voip38-static.xml', template)
    atomic(generation / 'nftables.conf', firewall)
    present = subprocess.run(['nft', 'list', 'table', 'inet', 'voip38_build'], capture_output=True).returncode == 0
    run(['nft', '-c', '-f', '-'], input=(('delete table inet voip38_build\n' if present else '') + firewall).encode())
    ET.fromstring(xml)
    deploy_scripts()
    previous_xml = Path('/etc/freeswitch/freeswitch.xml').read_bytes()
    static_path = Path('/etc/freeswitch/voip38-static.xml')
    previous_static = static_path.read_bytes() if static_path.exists() else None
    previous_fw = Path('/etc/nftables.conf').read_text()
    try:
        apply_firewall(firewall)
        atomic(static_path, template, 0o640, True)
        atomic('/etc/freeswitch/freeswitch.xml', xml, 0o640, True)
        if command == 'start':
            seed_native_cache(payload)
            config = next(c for c in ET.fromstring(template).iter('configuration') if c.get('name') == 'event_socket.conf')
            secret = next(n.get('value') for n in config.iter('param') if n.get('name') == 'password')
            atomic('/root/.fs_cli_conf', '[default]\nhost => 127.0.0.1\nport => 8021\npassword => ' + secret + '\n')
            atomic('/root/voip38-esl.json', json.dumps({'password': secret}))
        if command == 'sync' and (previous_static != template or previous_xml != xml):
            result = run(['/usr/local/bin/fs_cli', '-x', 'reloadxml']).stdout.decode()
            if '[Success]' not in result:
                raise RuntimeError('reload failed')
    except Exception:
        atomic('/etc/freeswitch/freeswitch.xml', previous_xml, 0o640, True)
        if previous_static is not None:
            atomic(static_path, previous_static, 0o640, True)
        else:
            static_path.unlink(missing_ok=True)
        apply_firewall(previous_fw)
        raise
    if old.exists():
        previous = STATE / 'previous.new'
        previous.unlink(missing_ok=True)
        previous.symlink_to(old.resolve())
        previous.replace(STATE / 'previous')
    link = STATE / 'current.new'
    link.unlink(missing_ok=True)
    link.symlink_to(generation)
    link.replace(old)
    result = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'mode': MODE,
              'source': source, 'address': address, 'interface': interface, 'lan_interface': lan_interface, 'contexts': contexts,
              'firewall_host_lines': count, 'firewall_unique_networks': counts,
              'gateways': len(list(xml_fragment(payload['getGateways']).iter('gateway'))),
              'gateway_users': len(list(xml_fragment(payload['getGatewayUsers']).iter('user'))),
              'customer_cards': len(list(xml_fragment(payload['getCardsConfig']).iter('user'))),
              'production_calls_blocked': MODE == 'BUILD', 'production_db_egress_blocked': MODE == 'BUILD',
              'gateway_registration_and_pings_disabled': MODE == 'BUILD',
              'generation': generation.name, 'xml_sha256': hashlib.sha256(xml).hexdigest()}
    result['native_xml_refresh_on_reloadxml'] = True
    result['xml_template_sha256'] = hashlib.sha256(template).hexdigest()
    atomic(STATE / 'status.json', json.dumps(result, indent=2))
    (STATE / 'last-error.json').unlink(missing_ok=True)
    # Keep current and previous generations, without accumulating credential-bearing payloads.
    retain = {old.resolve()}
    if (STATE / 'previous').exists():
        retain.add((STATE / 'previous').resolve())
    for directory in STATE.glob('generation-*'):
        if directory not in retain:
            shutil.rmtree(directory)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
