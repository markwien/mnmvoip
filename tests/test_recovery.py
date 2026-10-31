import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from reassemble import reassemble

spec = importlib.util.spec_from_file_location('guard', ROOT / 'source/recovery/voip50_check_interface.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'new_vm_uuid': 'new', 'old_vm_uuid': 'old',
                     'internal': {'interface': 'enX0', 'mac': '02:00:00:00:00:01'},
                     'public': {'interface': 'enX1', 'mac': '02:00:00:00:00:02'}}
        self.proof = {'new_vm_uuid': 'new', 'old_vm_uuid': 'old',
                      'user_authorized_live': True, 'old_vm_halted': True,
                      'old_vifs_inactive': True, 'checked_epoch': 1000}
        self.commission = {'vm_uuid': 'new', 'authorized': True, 'plan': copy.deepcopy(self.plan)}

    def check(self, **changes):
        args = dict(plan=self.plan, interface='enX0', role='internal',
                    mac='02:00:00:00:00:01', vm_uuid='new', mode='BUILD',
                    commission=None, proof=self.proof, now=1001)
        args.update(changes)
        return guard.validate(**args)

    def test_first_activation_requires_fresh_proof(self):
        self.assertTrue(self.check())
        with self.assertRaises(PermissionError):
            self.check(now=1900)

    def test_reboot_uses_matching_commission_after_old_proof_expires(self):
        self.assertTrue(self.check(commission=self.commission, mode='LIVE', now=900000))

    def test_missing_or_false_shutdown_evidence_rejected(self):
        for field in ['user_authorized_live', 'old_vm_halted', 'old_vifs_inactive']:
            proof = dict(self.proof, **{field: False})
            with self.assertRaises(PermissionError):
                self.check(proof=proof)

    def test_wrong_vm_mac_or_role_rejected(self):
        for changes in [{'vm_uuid': 'clone'}, {'mac': '02:00:00:00:00:09'},
                        {'interface': 'enX1'}, {'role': 'unknown'}]:
            with self.assertRaises(ValueError):
                self.check(**changes)

    def test_changed_commission_plan_or_mode_rejected(self):
        for changes in [{'mode': 'BUILD'}, {'commission': dict(self.commission, authorized=False)},
                        {'commission': dict(self.commission, vm_uuid='other')}]:
            args = {'commission': self.commission, 'mode': 'LIVE'}
            args.update(changes)
            with self.assertRaises(PermissionError):
                self.check(**args)
        changed = copy.deepcopy(self.commission)
        changed['plan']['internal']['mac'] = '02:00:00:00:00:09'
        with self.assertRaises(PermissionError):
            self.check(commission=changed, mode='LIVE')


class ReassemblyTests(unittest.TestCase):
    def fixture(self, directory):
        payload = b'encrypted-fixture-not-real-credentials'
        part = directory / 'fixture.part-000'
        part.write_bytes(payload)
        h = hashlib.sha256(payload).hexdigest()
        manifest = directory / 'manifest.json'
        manifest.write_text(json.dumps({'artifacts': [{'file': 'fixture.gpg', 'bytes': len(payload),
                           'sha256': h, 'parts': [{'file': part.name, 'bytes': len(payload), 'sha256': h}]}]}))
        return payload, part, manifest

    def test_reassembly_and_idempotency(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            payload, part, manifest = self.fixture(path)
            reassemble(manifest, path / 'out')
            reassemble(manifest, path / 'out')
            self.assertEqual((path / 'out/fixture.gpg').read_bytes(), payload)

    def test_corruption_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            payload, part, manifest = self.fixture(path)
            part.write_bytes(b'X' * len(payload))
            with self.assertRaises(ValueError):
                reassemble(manifest, path / 'out')
            self.assertFalse((path / 'out/fixture.gpg').exists())

    def test_path_traversal_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            payload, part, manifest = self.fixture(path)
            data = json.loads(manifest.read_text())
            data['artifacts'][0]['parts'][0]['file'] = '../escape'
            manifest.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                reassemble(manifest, path / 'out')


if __name__ == '__main__':
    unittest.main()
