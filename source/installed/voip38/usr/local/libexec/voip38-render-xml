#!/usr/bin/python3
"""Unprivileged FreeSWITCH XML preprocessor callback. Stdout is XML only."""
import copy
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.request
import uuid
import xml.etree.ElementTree as ET

CONFIG = Path('/etc/freeswitch/voip38-static.xml')
CACHE = Path('/var/lib/freeswitch/xml-cache')
ACTIONS = ['getGateways', 'getGatewayUsers', 'getCardsConfig', 'ivrXML']


def parse(data):
    text = re.sub(r'<\?xml[^>]*\?>', '', data.decode())
    if '<html' in text.lower() or '<!doctype' in text.lower():
        raise ValueError('unexpected HTML')
    root = ET.fromstring('<reference>' + text + '</reference>')
    if list(root.iter('X-PRE-PROCESS')):
        raise ValueError('remote preprocessor command rejected')
    return root


def validate(payload):
    for name in ACTIONS:
        root = parse(payload[name])
        expected = {'getGateways': 'gateway', 'getGatewayUsers': 'user', 'getCardsConfig': 'user', 'ivrXML': 'menu'}[name]
        if name != 'getCardsConfig' and not list(root.iter(expected)):
            raise ValueError('empty required XML')


def set_param(parent, name, value):
    node = next((e for e in parent.findall('param') if e.get('name') == name), None)
    if node is None:
        node = ET.SubElement(parent, 'param', name=name)
    node.set('value', value)


def atomic(path, data):
    temp = path.with_name(path.name + '.new')
    temp.write_bytes(data if isinstance(data, bytes) else data.encode())
    temp.chmod(0o600)
    temp.replace(path)


def main():
    os.umask(0o077)
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (CACHE / 'render.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    root = ET.parse(CONFIG).getroot()
    variables = {'base_dir': '/opt/freeswitch', 'conf_dir': '/etc/freeswitch',
                 'sounds_dir': '/var/lib/freeswitch/sounds', 'certs_dir': '/etc/freeswitch/ssl'}
    for e in root.findall('X-PRE-PROCESS'):
        key, sep, value = e.get('data', '').partition('=')
        if e.get('cmd') == 'set' and sep:
            variables[key] = value
    variables['local_ip_v4'] = variables.get('domain', '')
    switch_id = variables['switchid']
    if not switch_id.isdigit() or variables.get('voip38_build_hold') not in ['true', 'false']:
        raise ValueError('operating mode identity missing')
    hold = variables['voip38_build_hold'] == 'true'
    current = CACHE / 'current'
    source = 'panel'
    payload = {}
    try:
        for name in ACTIONS:
            suffix = '?switchid=' + switch_id if name != 'ivrXML' else ''
            origin = 'http://192.168.1.60' if hold else 'https://www.telemediacloud.com'
            host = 'config.telemediacloud.com' if hold else 'www.telemediacloud.com'
            request = urllib.request.Request(origin + '/configHandler/' + name + suffix,
                                             headers={'Host': host})
            with urllib.request.urlopen(request, timeout=6) as response:
                data = response.read(8 * 1024 * 1024)
                if response.status != 200 or len(data) >= 8 * 1024 * 1024:
                    raise ValueError('bad HTTP response')
                payload[name] = data
        validate(payload)
    except Exception:
        if not current.exists():
            raise RuntimeError('no valid XML fallback available')
        payload = {name: (current / name).read_bytes() for name in ACTIONS}
        validate(payload)
        source = 'last-known-good'
    configuration = root.find("section[@name='configuration']")
    for conf in configuration.findall('configuration'):
        if conf.get('name') == 'sofia.conf':
            for profile in conf.iter('profile'):
                gateways = profile.find('gateways')
                gateways.clear()
                for item in parse(payload['getGateways']):
                    gateway = copy.deepcopy(item)
                    if hold:
                        set_param(gateway, 'register', 'false')
                        set_param(gateway, 'ping', '0')
                    gateways.append(gateway)
        if conf.get('name') == 'ivr.conf':
            menus = conf.find('menus')
            menus.clear()
            for menu in parse(payload['ivrXML']).iter('menu'):
                menus.append(copy.deepcopy(menu))
    domain = root.find("section[@name='directory']/domain")
    users = domain.find('users')
    users.clear()
    for action in ['getGatewayUsers', 'getCardsConfig']:
        for user in parse(payload[action]).iter('user'):
            users.append(copy.deepcopy(user))
    # The master document handles global assignments. Expand only double-dollar
    # preprocessor variables here; ordinary channel variables stay intact.
    def expand(text):
        for _ in range(15):
            changed = re.sub(r'\$\$\{([^}]+)\}', lambda m: variables.get(m.group(1), m.group(0)), text)
            if changed == text:
                return text
            text = changed
        return text
    sections = []
    for section in root.findall('section'):
        for node in section.iter():
            for name, value in list(node.attrib.items()):
                node.set(name, expand(value))
            if node.text:
                node.text = expand(node.text)
        sections.append(ET.tostring(section, encoding='unicode'))
    output = '\n'.join(sections)
    if re.search(r'\$\$\{[^}]+\}', output):
        raise ValueError('unresolved preprocessor variable')
    ET.fromstring('<document>' + output + '</document>')
    if source == 'panel':
        generation = CACHE / ('generation-' + uuid.uuid4().hex)
        generation.mkdir(mode=0o700)
        for name, data in payload.items():
            atomic(generation / name, data)
        link = CACHE / 'current.new'
        link.unlink(missing_ok=True)
        link.symlink_to(generation)
        link.replace(current)
        for old in CACHE.glob('generation-*'):
            if old != generation:
                shutil.rmtree(old)
    status = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source': source, 'render_id': uuid.uuid4().hex,
              'gateways': len(list(parse(payload['getGateways']).iter('gateway'))),
              'gateway_users': len(list(parse(payload['getGatewayUsers']).iter('user'))),
              'customer_cards': len(list(parse(payload['getCardsConfig']).iter('user'))),
              'hold_active': hold}
    atomic(CACHE / 'status.json', json.dumps(status, indent=2))
    sys.stdout.write(output)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print server payloads, passwords, URLs or connection strings.
        print('XML render failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
