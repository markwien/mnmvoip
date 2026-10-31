#!/usr/bin/python3
"""VoIP50 network guard: fresh first activation, persistent authorized reboots.

First activation still requires a fresh shutdown/authorization proof. Subsequent
boots may use the exact persistent commissioning established by LIVE startup.
"""
import json
import os
from pathlib import Path
import sys
import time


def validate(plan, interface, role, mac, vm_uuid, mode, commission, proof, now):
    if role not in ['internal', 'public']:
        raise ValueError('unknown network role')
    expected = plan[role]
    if interface != expected['interface'] or mac.lower() != expected['mac'].lower():
        raise ValueError('interface role or MAC mismatch')
    if interface == plan['internal' if role == 'public' else 'public']['interface']:
        raise ValueError('network roles overlap')
    if vm_uuid != plan['new_vm_uuid']:
        raise ValueError('guest VM UUID differs from plan')
    if commission is not None:
        if mode != 'LIVE' or commission.get('authorized') is not True:
            raise PermissionError('invalid commissioning mode/authorization')
        if commission.get('vm_uuid') != vm_uuid or commission.get('plan') != plan:
            raise PermissionError('commissioning does not match current VM and plan')
        return True
    if not all(proof.get(key) is True for key in ['user_authorized_live', 'old_vm_halted', 'old_vifs_inactive']):
        raise PermissionError('first activation has not been authorized and checked')
    if proof.get('old_vm_uuid') != plan['old_vm_uuid'] or proof.get('new_vm_uuid') != vm_uuid:
        raise ValueError('activation VM identity mismatch')
    if not 0 <= now - proof.get('checked_epoch', 0) < 900:
        raise PermissionError('first activation proof expired')
    return True


def protected_json(path):
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise PermissionError('control JSON must be root-owned and mode 0600')
    return json.loads(path.read_text())


def main():
    if os.geteuid() != 0:
        raise PermissionError('root required')
    plan = protected_json(Path('/etc/voip50/network-plan.json'))
    commission_file = Path('/etc/voip50/live-commissioned.json')
    commission = protected_json(commission_file) if commission_file.exists() else None
    proof = {} if commission is not None else protected_json(Path('/root/voip50-build/cutover/authorization.json'))
    interface, role = sys.argv[1:]
    if role not in ['internal', 'public'] or interface != plan[role]['interface']:
        raise ValueError('unexpected interface or role')
    return validate(plan, interface, role, Path('/sys/class/net', interface, 'address').read_text().strip(),
                    Path('/sys/hypervisor/uuid').read_text().strip(),
                    Path('/etc/voip50/mode').read_text().strip(), commission, proof, time.time())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Interface activation blocked: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
