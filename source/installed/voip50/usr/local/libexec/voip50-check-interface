#!/usr/bin/python3
"""Read-only interface/authorization guard for a later, separate cutover."""
import json
import os
from pathlib import Path
import sys
import time

def validate(plan,interface,role,mac,proof,now):
    if role not in ['internal','public']:raise ValueError('unknown network role')
    expected=plan[role]
    if interface!=expected['interface'] or mac.lower()!=expected['mac'].lower():raise ValueError('interface role or MAC mismatch')
    if interface==plan['internal' if role=='public' else 'public']['interface']:raise ValueError('network roles overlap')
    if not all(proof.get(k) is True for k in ['user_authorized_live','old_vm_halted','old_vifs_inactive']):raise PermissionError('live cutover has not been authorized and checked')
    if proof.get('old_vm_uuid')!=plan['old_vm_uuid'] or proof.get('new_vm_uuid')!=plan['new_vm_uuid']:raise ValueError('VM identity mismatch')
    if not 0<=now-proof.get('checked_epoch',0)<900:raise PermissionError('cutover proof is stale')
    return True

if __name__=='__main__':
    try:
        plan_path=Path('/etc/voip50/network-plan.json')
        proof_path=Path('/root/voip50-build/cutover/authorization.json')
        for p in [plan_path,proof_path]:
            s=p.stat()
            if s.st_uid!=0 or s.st_mode & 0o077:raise PermissionError('unprotected network plan or authorization')
        plan=json.loads(plan_path.read_text());proof=json.loads(proof_path.read_text())
        interface,role=sys.argv[1:]
        validate(plan,interface,role,Path('/sys/class/net',interface,'address').read_text().strip(),proof,time.time())
    except Exception as error:
        print('Interface activation blocked: '+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
