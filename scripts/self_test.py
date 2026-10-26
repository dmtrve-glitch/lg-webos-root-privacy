#!/usr/bin/env python3
"""Offline behavior tests. No TV, live mount, systemctl, root or reboot."""
import contextlib
import hashlib
from http.server import HTTPServer
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tv_policy as policy
import tv_bridge as bridge
import tv_audit as audit


def plan():
    return {'format': 1, 'identity': {'model': 'TEST-MODEL', 'software_version': 'TEST-VERSION'},
            'guard_seconds': 60, 'targets': [
                {'path': '/usr/sbin/' + name, 'sha256': digit * 64, 'units': [name + '.service'],
                 'role': 'Test role', 'evidence': 'Test observation', 'impact': 'Test consequence'}
                for name, digit in [('contentminer', 'a'), ('nudge', 'b')]]}


class FakeSystem:
    def __init__(self):
        self.originals = {t['path']: t['sha256'] for t in plan()['targets']}
        self.mounts = {}
        self.unit_state = {'contentminer.service': 'active', 'nudge.service': 'inactive'}
        self.running = [{'pid': 9000, 'exe': '/usr/sbin/contentminer'}]
        self.calls = []
        self.fail_bind = None
        self.fail_unmount = None

    def fingerprint(self, path):
        if path not in self.originals:
            raise OSError('Missing target')
        return self.originals[path]

    def mounted(self, path):
        return path in self.mounts

    def owned(self, path, stub):
        return self.mounts.get(path) == stub

    def bind(self, stub, path):
        self.calls.append(('bind', path))
        if path == self.fail_bind:
            raise RuntimeError('Injected bind failure')
        self.mounts[path] = stub

    def unmount(self, path):
        self.calls.append(('unmount', path))
        if path == self.fail_unmount:
            raise RuntimeError('Injected unmount failure')
        del self.mounts[path]

    def units(self, units):
        return {u: self.unit_state.get(u, 'unknown') for u in units}

    def change_units(self, verb, units):
        self.calls.append((verb, tuple(units)))
        for u in units:
            self.unit_state[u] = 'active' if verb == 'start' else 'inactive'

    def processes(self, paths):
        return [p for p in self.running if p['exe'] in paths]

    def stop_processes(self, paths):
        self.running = [p for p in self.running if p['exe'] not in paths]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        policy.save(str(self.state / 'plan.json'), plan())
        (self.state / 'disabled-service').write_bytes(policy.STUB)
        self.ops = FakeSystem()
        self.p = policy.Policy(str(self.state), self.ops)
        # Replace only process spawning with an offline pending guard state.
        def arm(stage):
            if policy.load(self.p.file('pending.json')):
                raise RuntimeError('Trial already pending')
            policy.save(self.p.file('pending.json'), {'token': 'test-token', 'stage': stage, 'deadline': time.time() + 60})
        self.p.arm = arm

    def tearDown(self):
        self.temp.cleanup()

    def test_apply_then_manual_rollback_restores_exact_active_units(self):
        self.p.apply()
        self.assertTrue(all(t['blocked'] for t in self.p.status()['targets']))
        self.assertEqual(self.p.status()['running'], [])
        result = self.p.rollback('Test')
        self.assertEqual(result['errors'], [])
        self.assertFalse(self.ops.mounts)
        self.assertEqual(self.ops.unit_state, {'contentminer.service': 'active', 'nudge.service': 'inactive'})

    def test_fingerprint_mismatch_prevents_every_mount(self):
        self.ops.originals['/usr/sbin/nudge'] = 'c' * 64
        with self.assertRaises(RuntimeError):
            self.p.apply()
        self.assertEqual(self.ops.calls, [])

    def test_partial_apply_failure_unmounts_successful_targets(self):
        self.ops.fail_bind = '/usr/sbin/nudge'
        with self.assertRaises(RuntimeError):
            self.p.apply()
        self.assertFalse(self.ops.mounts)
        self.assertTrue(self.p.status()['disabled'])

    def test_foreign_mount_is_never_replaced_or_unmounted(self):
        self.ops.mounts['/usr/sbin/contentminer'] = '/another-policy/stub'
        with self.assertRaises(RuntimeError):
            self.p.apply()
        result = self.p.rollback('Test')
        self.assertTrue(result['errors'])
        self.assertEqual(self.ops.mounts['/usr/sbin/contentminer'], '/another-policy/stub')

    def test_expiry_rolls_back_even_without_host_reply(self):
        self.p.apply()
        pending = policy.load(self.p.file('pending.json'))
        pending['deadline'] = time.time() - 1
        policy.save(self.p.file('pending.json'), pending)
        result = self.p.expire('test-token')
        self.assertEqual(result['errors'], [])
        self.assertFalse(self.ops.mounts)

    def test_stale_guard_cannot_rollback_a_new_trial(self):
        self.p.apply()
        self.assertIsNone(self.p.expire('old-token'))
        self.assertTrue(self.ops.mounts)

    def test_confirm_cancels_guard_and_does_not_claim_boot_validation(self):
        self.p.apply()
        policy.save(self.p.file('needs-boot-validation.json'), {'created': time.time()})
        self.p.confirm()
        self.assertIsNone(policy.load(self.p.file('pending.json')))
        self.assertTrue(self.p.status()['needs_boot_validation'])
        self.assertIsNone(self.p.expire('test-token'))

    def test_boot_confirm_clears_first_boot_marker(self):
        policy.save(self.p.file('needs-boot-validation.json'), {'created': time.time()})
        self.p.apply('boot')
        self.p.confirm()
        self.assertFalse(self.p.status()['needs_boot_validation'])

    def test_late_confirm_performs_rollback_instead_of_committing(self):
        self.p.apply()
        pending = policy.load(self.p.file('pending.json'))
        pending['deadline'] = time.time() - 1
        policy.save(self.p.file('pending.json'), pending)
        with self.assertRaises(RuntimeError):
            self.p.confirm()
        self.assertFalse(self.ops.mounts)

    def test_unmount_failure_is_reported_and_disabled_marker_remains(self):
        self.p.apply()
        self.ops.fail_unmount = '/usr/sbin/contentminer'
        result = self.p.rollback('Test')
        self.assertTrue(result['errors'])
        self.assertTrue(self.p.status()['disabled'])
        self.assertIn('/usr/sbin/contentminer', self.ops.mounts)

    def test_missing_target_is_not_silently_omitted(self):
        self.p.apply()
        del self.ops.mounts['/usr/sbin/nudge']
        with self.assertRaises(RuntimeError):
            self.p.verify()

    def test_no_trial_timer_reset(self):
        self.p.apply()
        before = policy.load(self.p.file('pending.json'))
        with self.assertRaises(RuntimeError):
            self.p.apply()
        self.assertEqual(policy.load(self.p.file('pending.json')), before)

    def test_critical_paths_and_units_are_rejected(self):
        for field, value in [('path', '/usr/bin/python'), ('units', ['connman.service'])]:
            candidate = plan()
            candidate['targets'][0][field] = value
            with self.assertRaises(ValueError):
                policy.validate_plan(candidate)


class BridgeTests(unittest.TestCase):
    def test_module_hash_checked_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'slopbro.py'
            module.write_text("raise RuntimeError('Must not execute')", encoding='utf8')
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'files': [{'path': 'slopbro.py', 'sha256': '0' * 64}]}), encoding='utf8')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                bridge.reviewed_module(module, manifest)

    def test_private_ipv4_validation(self):
        self.assertEqual(bridge.private_ip('192.168.1.2'), '192.168.1.2')
        for address in ['127.0.0.1', '0.0.0.0', '8.8.8.8', '::1']:
            with self.assertRaises(Exception):
                bridge.private_ip(address)

    def test_token_asset_and_body_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory).resolve()
            (assets / 'audit.py').write_bytes(b'public-script')
            result, done = {}, threading.Event()
            handler = bridge.make_handler('127.0.0.1', 'test-token', b'test-page', result, done, assets)
            server = HTTPServer(('127.0.0.1', 0), handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = 'http://127.0.0.1:' + str(server.server_port)
            try:
                self.assertEqual(urlopen(base + '/maint-test-token.html', timeout=2).read(), b'test-page')
                self.assertEqual(urlopen(base + '/assets-test-token/audit.py', timeout=2).read(), b'public-script')
                for path in ['/maint-wrong.html', '/assets-test-token/../secret', '/assets-test-token/%2e%2e', '/assets-test-token/missing']:
                    with self.assertRaises(HTTPError):
                        urlopen(base + path, timeout=2)
                request = Request(base + '/result-test-token', data=b'{}', headers={'Content-Type': 'application/json'})
                self.assertEqual(urlopen(request, timeout=2).read(), b'OK')
                self.assertTrue(done.is_set())
                request = Request(base + '/result-test-token', data=b'{}', headers={'Content-Length': str(3 * 1024 * 1024)})
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(request, timeout=2)
                self.assertEqual(rejected.exception.code, 413)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)


class AuditTests(unittest.TestCase):
    def test_missing_file_and_bounded_command(self):
        self.assertFalse(audit.file_info('/not-a-tv-file')['exists'])
        result = audit.bounded([sys.executable, '-c', "print('x' * 100)"], limit=8)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['text']), 8)

    def test_audit_command_cannot_hang_forever(self):
        start = time.time()
        result = audit.bounded([sys.executable, '-c', 'import time; time.sleep(20)'], seconds=0.2)
        self.assertTrue(result['timed_out'])
        self.assertLess(time.time() - start, 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
