#!/usr/bin/env python
"""Bounded, read-only webOS inventory. Run on the TV with Python 2.7 or 3."""
from __future__ import print_function
import glob
import hashlib
import json
import os
import platform
import stat
import subprocess
import tempfile
import time

NAMES = 'acr2 admanager adoverlay-service captureservice contentminer nudge livepick rdxd uploadd remotelogger iconnectivity'.split()
UNITS = 'contentminer nudge livepick rdxd uploadd remotelogger'.split()


def bounded(args, seconds=2, limit=8192):
    try:
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT)
            proc.stdin.close()
            deadline = time.time() + seconds
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.05)
            expired = proc.poll() is None
            if expired:
                proc.kill()
            proc.wait()
            output.seek(0)
            data = output.read(limit + 1)
        return {'exit': proc.returncode, 'timed_out': expired, 'truncated': len(data) > limit, 'text': data[:limit].decode('utf8', 'replace')}
    except (OSError, IOError) as error:
        return {'error': str(error)}


def file_info(path):
    result = {'path': path, 'exists': os.path.lexists(path)}
    if not result['exists']:
        return result
    try:
        info = os.lstat(path)
        result.update({'symlink': stat.S_ISLNK(info.st_mode), 'size': info.st_size, 'mode': oct(stat.S_IMODE(info.st_mode))})
        if not stat.S_ISREG(info.st_mode):
            return result
        h = hashlib.sha256()
        with open(path, 'rb') as src:
            result['elf'] = src.read(4) == b'\x7fELF'
            src.seek(0)
            for block in iter(lambda: src.read(65536), b''):
                h.update(block)
        result['sha256'] = h.hexdigest()
    except (OSError, IOError) as error:
        result['error'] = str(error)
    return result


def collect():
    paths = ['/usr/sbin/' + n for n in NAMES]
    processes = []
    for proc in glob.glob('/proc/[0-9]*'):
        try:
            exe = os.readlink(proc + '/exe').replace(' (deleted)', '')
            if exe in paths or os.path.basename(exe) in ('dropbear', 'sshd', 'telnetd'):
                processes.append({'pid': int(proc.rsplit('/', 1)[1]), 'exe': exe})
        except OSError:
            pass
    releases = {}
    # Avoid serial/MAC/client credentials and unrestricted log collection.
    for path in ['/etc/os-release', '/etc/starfish-release', '/etc/webos-release']:
        try:
            with open(path, 'rb') as src:
                releases[path] = src.read(4096).decode('utf8', 'replace')
        except IOError:
            pass
    mounts = []
    try:
        with open('/proc/mounts') as src:
            for line in src:
                cells = line.split()
                if cells[1] in paths or cells[1] in ('/', '/var', '/media/developer'):
                    mounts.append({'path': cells[1], 'type': cells[2], 'options': cells[3]})
    except IOError:
        pass
    writable = {}
    for path in ['/var/lib/webosbrew', '/media/developer']:
        try:
            space = os.statvfs(path)
            writable[path] = {'write_access': os.access(path, os.W_OK), 'available_bytes': space.f_bavail * space.f_frsize}
        except OSError:
            pass
    return {'audit_format': 1, 'machine': platform.machine(), 'kernel': platform.release(),
            'uid': os.geteuid() if hasattr(os, 'geteuid') else None,
            'python': platform.python_version(), 'releases': releases,
            'files': [file_info(path) for path in paths], 'processes': processes,
            'mounts': mounts, 'writable': writable,
            'init_hooks': sorted(glob.glob('/var/lib/webosbrew/init.d/*')),
            'unit_details': {u + '.service': bounded(['/bin/systemctl', '--system', 'show', u + '.service',
                '--property=ActiveState,SubState,FragmentPath,ExecStart']) for u in UNITS}}


if __name__ == '__main__':
    print(json.dumps(collect(), sort_keys=True, indent=2))
