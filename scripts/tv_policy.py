#!/usr/bin/env python
"""Explicit, reversible LG webOS ELF policy. Python 2.7/3, standard library.

CLI runs on the TV. Importing this module never changes the system.
"""
from __future__ import print_function
import argparse
import contextlib
import glob
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

STUB = b'#!/bin/sh\nexit 0\n'
CANDIDATES = set('acr2 admanager adoverlay-service captureservice contentminer nudge livepick rdxd uploadd remotelogger'.split())


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as src:
        for block in iter(lambda: src.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    fd, tmp = tempfile.mkstemp(prefix='.write-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, sort_keys=True, indent=2)
            out.flush()
            os.fsync(out.fileno())
        getattr(os, 'replace', os.rename)(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load(path, default=None):
    try:
        with open(path) as src:
            return json.load(src)
    except IOError:
        return default


def validate_plan(plan):
    if plan.get('format') != 1 or not plan.get('identity', {}).get('model') or not plan['identity'].get('software_version'):
        raise ValueError('Plan requires format=1 and exact model/software_version')
    targets = plan.get('targets', [])
    if not 1 <= len(targets) <= 10:
        raise ValueError('Select 1..10 independently reviewed targets')
    if not 60 <= plan.get('guard_seconds', 180) <= 900:
        raise ValueError('guard_seconds must be 60..900')
    seen = set()
    for target in targets:
        path = target.get('path', '')
        # Deliberately narrow: new component families require code review, not a flag.
        if path not in ['/usr/sbin/' + n for n in CANDIDATES] or path in seen:
            raise ValueError('Unsupported or duplicate target: ' + path)
        seen.add(path)
        if not re.match(r'^[a-f0-9]{64}$', target.get('sha256', '')):
            raise ValueError('An original ELF SHA-256 is required: ' + path)
        if any(not target.get(k) for k in ('role', 'evidence', 'impact')):
            raise ValueError('Each target needs role, evidence and impact')
        allowed_units = set(n + '.service' for n in CANDIDATES)
        if any(u not in allowed_units for u in target.get('units', [])):
            raise ValueError('Unit outside reviewed component families')
    return plan


class System(object):
    def call(self, args):
        return subprocess.check_call(args, stdin=open('/dev/null', 'rb'))

    def fingerprint(self, path):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
            raise RuntimeError('Expected a regular non-symlink ELF: ' + path)
        with open(path, 'rb') as src:
            if src.read(4) != b'\x7fELF':
                raise RuntimeError('Expected ELF: ' + path)
        return digest(path)

    def mounted(self, path):
        with open('/proc/mounts') as src:
            return any(line.split()[1] == path for line in src)

    def owned(self, path, stub):
        try:
            a, b = os.stat(path), os.stat(stub)
            return self.mounted(path) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and digest(path) == digest(stub)
        except OSError:
            return False

    def bind(self, stub, path):
        self.call(['/bin/mount', '--bind', stub, path])
        self.call(['/bin/mount', '-o', 'bind,remount,ro', stub, path])

    def unmount(self, path):
        self.call(['/bin/umount', path])

    def units(self, units):
        result = {}
        for unit in units:
            p = subprocess.Popen(['/bin/systemctl', '--system', 'is-active', unit], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result[unit] = p.communicate()[0].decode('utf8', 'replace').strip()
        return result

    def change_units(self, verb, units):
        if units:
            self.call(['/bin/systemctl', '--system', verb, '--no-block'] + units)

    def processes(self, paths):
        result = []
        for proc in glob.glob('/proc/[0-9]*'):
            try:
                exe = os.readlink(proc + '/exe').replace(' (deleted)', '')
                if exe in paths:
                    result.append({'pid': int(proc.rsplit('/', 1)[1]), 'exe': exe})
            except OSError:
                pass
        return result

    def stop_processes(self, paths):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for proc in self.processes(paths):
                # Recheck PID identity immediately before signaling.
                try:
                    if os.readlink('/proc/%s/exe' % proc['pid']).replace(' (deleted)', '') == proc['exe']:
                        os.kill(proc['pid'], sig)
                except OSError:
                    pass
            time.sleep(0.5)


class Policy(object):
    def __init__(self, state, system=None):
        self.state = state
        self.ops = system or System()
        self.plan = validate_plan(load(self.file('plan.json'), {}))
        self.paths = [t['path'] for t in self.plan['targets']]
        self.unit_names = sorted(set(u for t in self.plan['targets'] for u in t.get('units', [])))
        self.stub = self.file('disabled-service')
        if digest(self.stub) != hashlib.sha256(STUB).hexdigest():
            raise RuntimeError('Policy stub was modified')

    def file(self, name):
        return os.path.join(self.state, name)

    def remove(self, name):
        try:
            os.unlink(self.file(name))
        except OSError:
            if os.path.exists(self.file(name)):
                raise

    def status(self):
        return {'disabled': os.path.exists(self.file('disabled.json')),
                'pending': load(self.file('pending.json')),
                'needs_boot_validation': os.path.exists(self.file('needs-boot-validation.json')),
                'targets': [{'path': p, 'blocked': self.ops.owned(p, self.stub)} for p in self.paths],
                'running': self.ops.processes(self.paths), 'units': self.ops.units(self.unit_names)}

    def verify(self):
        result = self.status()
        if result['disabled'] or not all(t['blocked'] for t in result['targets']) or result['running']:
            raise RuntimeError('A selected target is missing, unblocked or running')
        if any(s not in ('inactive', 'failed') for s in result['units'].values()):
            raise RuntimeError('A selected unit has not stopped or is unknown')
        return result

    def preflight(self):
        for target in self.plan['targets']:
            path = target['path']
            if self.ops.owned(path, self.stub):
                continue
            if self.ops.mounted(path):
                raise RuntimeError('Foreign mount; do not overwrite another policy: ' + path)
            if self.ops.fingerprint(path) != target['sha256']:
                raise RuntimeError('Original hash changed, possibly firmware update: ' + path)

    def arm(self, stage):
        if load(self.file('pending.json')):
            raise RuntimeError('An existing trial is pending; inspect instead of resetting its timer')
        token = uuid.uuid4().hex
        pending = {'token': token, 'stage': stage, 'deadline': time.time() + self.plan.get('guard_seconds', 180)}
        save(self.file('pending.json'), pending)
        log = open(self.file('guard.log'), 'ab')
        null = open('/dev/null', 'rb')
        child = subprocess.Popen([sys.executable, os.path.abspath(__file__), '--state', self.state, 'guard', '--token', token],
                                 stdin=null, stdout=log, stderr=log, close_fds=True, preexec_fn=os.setsid)
        for unused in range(50):
            ready = load(self.file('guard-ready.json'), {})
            if ready.get('token') == token:
                return
            if child.poll() is not None:
                break
            time.sleep(0.1)
        self.remove('pending.json')
        raise RuntimeError('Independent rollback guard did not become ready; nothing was applied')

    def apply(self, stage='trial'):
        if os.path.exists(self.file('disabled.json')):
            raise RuntimeError('Policy is disabled; review and initialize a new session')
        self.preflight()  # Validate every original before the first mount.
        if not os.path.exists(self.file('baseline.json')):
            save(self.file('baseline.json'), {'units': self.ops.units(self.unit_names), 'plan': self.plan})
        if stage == 'trial' or os.path.exists(self.file('needs-boot-validation.json')):
            self.arm(stage)
        try:
            for path in self.paths:
                if not self.ops.owned(path, self.stub):
                    self.ops.bind(self.stub, path)
            self.ops.change_units('stop', self.unit_names)
            self.ops.stop_processes(self.paths)
            for unused in range(20):
                try:
                    result = self.verify()
                    break
                except RuntimeError:
                    time.sleep(0.25)
            else:
                raise RuntimeError('Targets did not stop')
            save(self.file('last-apply.json'), result)
            return result
        except Exception:
            self.rollback('Apply failed')
            raise

    def confirm(self):
        pending = load(self.file('pending.json'))
        if not pending:
            raise RuntimeError('No pending trial to confirm')
        if time.time() >= pending['deadline']:
            self.rollback('Confirmation arrived after deadline')
            raise RuntimeError('Trial expired and was rolled back')
        result = self.verify()
        save(self.file('last-confirmed.json'), {'stage': pending['stage'], 'time': time.time(), 'status': result})
        self.remove('pending.json')
        if pending['stage'] == 'boot':
            self.remove('needs-boot-validation.json')
        return result

    def rollback(self, reason):
        save(self.file('disabled.json'), {'reason': reason, 'time': time.time()})
        errors, restored = [], []
        for path in reversed(self.paths):
            try:
                if self.ops.owned(path, self.stub):
                    self.ops.unmount(path)
                    original = next(t['sha256'] for t in self.plan['targets'] if t['path'] == path)
                    if self.ops.fingerprint(path) != original:
                        raise RuntimeError('Restored file has a different original hash: ' + path)
                    restored.append(path)
                elif self.ops.mounted(path):
                    raise RuntimeError('Foreign mount still covers ' + path)
            except Exception as error:
                errors.append(str(error))
        if not errors:
            baseline = load(self.file('baseline.json'), {})
            active = [u for u, state in baseline.get('units', {}).items() if state == 'active']
            try:
                self.ops.change_units('start', active)
            except Exception as error:
                errors.append(str(error))
        self.remove('pending.json')
        result = {'reason': reason, 'restored': restored, 'errors': errors, 'disabled': True}
        save(self.file('last-rollback.json'), result)
        return result

    def expire(self, token):
        pending = load(self.file('pending.json'))
        if pending and pending['token'] == token and time.time() >= pending['deadline']:
            return self.rollback('Automatic rollback: trial/first boot was not confirmed')
        return None


@contextlib.contextmanager
def locked(state):
    import fcntl
    with open(os.path.join(state, '.lock'), 'a') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def check_state_path(path):
    if not re.match(r'^/var/lib/webosbrew/lg-privacy-[a-z0-9-]+$', path) or os.path.realpath(path) != path:
        raise ValueError('Use a new direct state directory /var/lib/webosbrew/lg-privacy-<session> without symlinks')


def initialize(state, plan_path):
    plan = validate_plan(load(plan_path, {}))
    if os.path.lexists(state):
        raise RuntimeError('State exists; do not replace a previous policy')
    ops = System()
    for target in plan['targets']:
        if ops.mounted(target['path']) or ops.fingerprint(target['path']) != target['sha256']:
            raise RuntimeError('Preflight failed before state initialization: ' + target['path'])
    os.mkdir(state, 448)
    save(os.path.join(state, 'plan.json'), plan)
    with open(os.path.join(state, 'disabled-service'), 'wb') as out:
        out.write(STUB)
    os.chmod(os.path.join(state, 'disabled-service'), 365)
    with open(__file__, 'rb') as src:
        data = src.read()
    with open(os.path.join(state, 'policy.py'), 'wb') as out:
        out.write(data)
    os.chmod(os.path.join(state, 'policy.py'), 448)
    return {'initialized': state, 'targets': len(plan['targets']), 'system_targets_changed': False}


def persist(policy):
    policy.verify()
    if not load(policy.file('last-confirmed.json')) or load(policy.file('pending.json')):
        raise RuntimeError('Confirm the interactive trial before persistence')
    init = '/var/lib/webosbrew/init.d'
    if not os.path.isdir(init) or os.path.realpath(init) != init:
        raise RuntimeError('Verified Homebrew init.d is required')
    hook = init + '/70-' + os.path.basename(policy.state)
    if os.path.lexists(hook):
        raise RuntimeError('Refusing to overwrite an existing hook')
    save(policy.file('needs-boot-validation.json'), {'created': time.time()})
    command = quote(sys.executable) + ' ' + quote(policy.file('policy.py')) + ' --state ' + quote(policy.state) + ' boot'
    text = '#!/bin/sh\n# Owned by ' + policy.state + '\n' + command + ' >> ' + quote(policy.file('boot.log')) + ' 2>&1\n'
    fd = os.open(hook, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 448)
    with os.fdopen(fd, 'w') as out:
        out.write(text)
    return {'hook': hook, 'first_boot_requires_confirmation': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('action', choices=['init', 'status', 'trial', 'confirm', 'persist', 'boot', 'rollback', 'guard'])
    parser.add_argument('--plan')
    parser.add_argument('--token')
    args = parser.parse_args()
    if not hasattr(os, 'geteuid') or os.geteuid() != 0 or not sys.platform.startswith('linux'):
        parser.error('Run on the Linux TV as root; this is not a laptop installer')
    check_state_path(args.state)
    if args.action == 'init':
        if not args.plan:
            parser.error('init requires --plan')
        result = initialize(args.state, args.plan)
    else:
        policy = Policy(args.state)
        if args.action == 'guard':
            if not args.token:
                parser.error('guard requires --token')
            save(policy.file('guard-ready.json'), {'token': args.token})
            while True:
                time.sleep(1)
                with locked(args.state):
                    pending = load(policy.file('pending.json'))
                    if not pending or pending['token'] != args.token:
                        return
                    if time.time() >= pending['deadline']:
                        print(json.dumps(policy.expire(args.token)))
                        return
        with locked(args.state):
            if args.action == 'boot' and os.path.exists(policy.file('disabled.json')):
                result = {'skipped': 'disabled'}
            else:
                try:
                    result = {'status': policy.status, 'trial': policy.apply, 'confirm': policy.confirm,
                              'persist': lambda: persist(policy), 'boot': lambda: policy.apply('boot'),
                              'rollback': lambda: policy.rollback('Manual rollback')}[args.action]()
                except Exception:
                    if args.action == 'boot':
                        policy.rollback('Boot failed; possible firmware change')
                    raise
    print(json.dumps(result, sort_keys=True))
    if isinstance(result, dict) and result.get('errors'):
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
