#!/usr/bin/env python3
"""Additional macOS process watcher. NOT a packet filter or a zero-leak kill switch."""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path.home() / 'Library/Application Support/VPN Guard'
LABEL = 'org.vpnguard.macos.watcher'
AGENT = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')


def run(args, timeout=2):
    env = dict(os.environ, LC_ALL='C')
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          check=True, env=env).stdout.strip()


def save(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(data, stream, ensure_ascii=False, indent=2)
    os.replace(temporary, path)


def load(path, default=None):
    if not path.exists() and default is not None:
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def route(family):
    address = '1.1.1.1' if family == 4 else '2606:4700:4700::1111'
    try:
        text = run(['/sbin/route', '-n', 'get', '-inet' if family == 4 else '-inet6', address])
    except subprocess.CalledProcessError:
        return None
    match = re.search(r'^\s*interface:\s*(\S+)\s*$', text, re.M)
    if not match:
        raise RuntimeError('Cannot identify the route interface')
    return match[1]


def tunnel(name):
    return bool(name and re.fullmatch(r'utun\d+', name))


def public_ip(family, interface):
    # Ignore system/environment proxies; check the actual tunnel, not a proxy's exit.
    url = 'https://api.ipify.org' if family == 4 else 'https://api6.ipify.org'
    value = run(['/usr/bin/curl', '--noproxy', '*', '--proxy', '', '--interface', interface,
                 '-' + str(family), '--fail', '--silent', '--show-error',
                 '--connect-timeout', '2', '--max-time', '3', url], timeout=4)
    ip = ipaddress.ip_address(value)
    if ip.version != family or not ip.is_global:
        raise RuntimeError('IP check did not return a public address')
    return str(ip)


def check_network(config):
    v4, v6 = route(4), route(6)
    if not tunnel(v4):
        return False, 'IPv4 route is outside a utun VPN'
    if v6 is not None and v6 != v4:
        return False, 'IPv6 route is outside the same VPN'
    if public_ip(4, v4) != config['expected_ipv4']:
        return False, 'VPN IPv4 address changed'
    if v6 is not None:
        if not config.get('expected_ipv6'):
            return False, 'IPv6 appeared: configure again with VPN connected'
        if public_ip(6, v6) != config['expected_ipv6']:
            return False, 'VPN IPv6 address changed'
    # Recheck routes after the potentially slow HTTPS requests.
    if (route(4), route(6)) != (v4, v6):
        return False, 'Routes changed during the check'
    return True, 'Expected tunnel route and public IP confirmed'


def validate(config):
    for key, family in [('expected_ipv4', 4), ('expected_ipv6', 6)]:
        value = config.get(key)
        if key == 'expected_ipv6' and value is None:
            continue
        ip = ipaddress.ip_address(value)
        if ip.version != family or not ip.is_global:
            raise ValueError('Invalid trusted public IP')
    paths = config.get('paths')
    if not isinstance(paths, list) or not paths:
        raise ValueError('No executable or application paths configured')
    forbidden = {'python', 'python3', 'bash', 'sh', 'zsh', 'Terminal.app', 'AmneziaVPN.app'}
    for path in paths:
        if not isinstance(path, str) or not os.path.isabs(path) or '\n' in path:
            raise ValueError('Paths must be absolute')
        if not ((path.endswith('.app') and (Path(path) / 'Contents').is_dir()) or native(path)):
            raise ValueError('Each path must be an installed .app bundle or native Mach-O executable (not a shell/Node.js script)')
        if Path(path).name in forbidden or Path(path).name.startswith('python3.'):
            raise ValueError('Do not target the VPN, Terminal, shell or Python interpreter')
    return config


def native(path):
    try:
        with open(path, 'rb') as stream:
            return stream.read(4) in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
    except (OSError, TypeError):
        return False


def matched(path, targets):
    return any(path == target or (target.endswith('.app') and
               path.startswith(target.rstrip('/') + '/Contents/')) for target in targets)


def processes():
    # libproc supplies executable paths without trusting command-line arguments.
    library = ctypes.CDLL('/usr/lib/libproc.dylib')
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    text = run(['/bin/ps', '-axo', 'pid=,ppid=,uid=,lstart=,stat='], timeout=3)
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 9 or int(fields[2]) != os.getuid():
            continue
        pid = int(fields[0])
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            continue
        path = os.path.realpath(os.fsdecode(buffer.value))
        result[pid] = dict(pid=pid, ppid=int(fields[1]), uid=int(fields[2]),
                           start=' '.join(fields[3:8]), path=path, stopped='T' in fields[8])
    return result


def same(first, second):
    return all(first.get(key) == second.get(key) for key in ('pid', 'uid', 'start', 'path'))


def selected(snapshot, targets, paused):
    chosen = {pid for pid, item in snapshot.items() if matched(item['path'], targets)}
    chosen.update(int(pid) for pid, item in paused.items()
                  if int(pid) in snapshot and same(item, snapshot[int(pid)]))
    while True:
        expanded = chosen | {pid for pid, item in snapshot.items() if item['ppid'] in chosen}
        if expanded == chosen:
            return chosen - {os.getpid()}
        chosen = expanded


class Controller:
    def __init__(self, directory=None, scan=processes, send=os.kill):
        directory = ROOT if directory is None else directory
        self.directory, self.scan, self.send = directory, scan, send
        self.paused = load(directory / 'paused.json', {})

    def persist(self):
        save(self.directory / 'paused.json', self.paused)

    def step(self, targets, healthy):
        snapshot = self.scan()
        for key, old in list(self.paused.items()):
            current = snapshot.get(int(key))
            if not current or not same(old, current):
                del self.paused[key]
        self.persist()
        if healthy:
            for key, old in list(self.paused.items()):
                current = self.scan().get(int(key))
                if current and same(old, current):
                    self.send(int(key), signal.SIGCONT)
                del self.paused[key]
                self.persist()
        else:
            for pid in selected(snapshot, targets, self.paused):
                old = snapshot[pid]
                if old['stopped'] or str(pid) in self.paused:
                    continue  # Never resume a process already paused by somebody else.
                current = self.scan().get(pid)
                if not current or not same(old, current) or current['stopped']:
                    continue
                self.paused[str(pid)] = current
                self.persist()  # Recovery record is saved before sending STOP.
                try:
                    self.send(pid, signal.SIGSTOP)
                except ProcessLookupError:
                    self.paused.pop(str(pid), None)
                    self.persist()


def lock(directory):
    import fcntl
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    stream = (directory / 'watcher.lock').open('a')
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        raise RuntimeError('Watcher is running. Unload the LaunchAgent first.')
    return stream


def watch():
    singleton = lock(ROOT)
    config = validate(load(ROOT / 'config.json'))
    controller = Controller()
    # First pause targets. No network request delays this initial action.
    controller.step(config['paths'], False)
    health = {'ok': False, 'reason': 'Checking VPN', 'checked': 0.0}
    mutex = threading.Lock()

    def probe():
        while True:
            try:
                ok, reason = check_network(config)
            except Exception as error:
                ok, reason = False, type(error).__name__ + ': network check failed'
            with mutex:
                health.update(ok=ok, reason=reason, checked=time.monotonic())
            time.sleep(1)

    threading.Thread(target=probe, daemon=True).start()
    while True:
        with mutex:
            healthy = health['ok'] and time.monotonic() - health['checked'] < 8
            reason = health['reason']
        if not healthy:
            reason = reason if not health['ok'] else 'Network check expired'
        try:
            controller.step(config['paths'], healthy)
            save(ROOT / 'status.json', dict(time=time.time(), healthy=healthy,
                 reason=reason, paused=len(controller.paused)))
        except Exception as error:
            save(ROOT / 'status.json', dict(time=time.time(), healthy=False,
                 reason='Process control failed: ' + type(error).__name__, paused=len(controller.paused)))
            raise  # launchd restarts the watcher; paused processes stay paused.
        time.sleep(0.5)


def configure():
    print('Enable the built-in Amnezia kill switch and connect your OWN VPN first.')
    print('This watcher is additional protection, with a detection delay; not a firewall.')
    if input('VPN connected and you understand this limitation? Type YES: ').strip() != 'YES':
        raise RuntimeError('Cancelled')
    v4, v6 = route(4), route(6)
    if not tunnel(v4) or (v6 is not None and v6 != v4):
        raise RuntimeError('IPv4 and any available IPv6 route must use the same utun VPN. Proxy-only/split-tunnel modes are unsupported.')
    ip4, ip6 = public_ip(4, v4), public_ip(6, v6) if v6 else None
    print('VPN interface:', v4, '\nIPv4:', ip4, '\nIPv6:', ip6 or 'no route')
    if input('Confirm these are your intended VPN exit addresses. Type TRUST: ').strip() != 'TRUST':
        raise RuntimeError('Cancelled')
    candidates = [Path('/Applications') / name for name in ('Claude.app','ChatGPT.app','Codex.app')]
    candidates += [Path.home() / 'Applications' / name for name in ('Claude.app','ChatGPT.app','Codex.app')]
    candidates += [Path(value) for name in ('claude','codex') if (value := shutil.which(name)) and native(value)]
    paths = sorted({os.path.realpath(p) for p in candidates if p.exists()})
    print('Auto-detected paths:', '\n'.join(paths) or '(none)')
    print('Add an absolute .app / native executable path, or press Enter to finish.')
    while value := input('Additional path: ').strip():
        paths.append(os.path.realpath(os.path.expanduser(value)))
    config = validate(dict(expected_ipv4=ip4, expected_ipv6=ip6, paths=sorted(set(paths))))
    print('The watcher will pause these paths and their detected child processes:\n' + '\n'.join(config['paths']))
    if input('Save this configuration? Type SAVE: ').strip() != 'SAVE':
        raise RuntimeError('Cancelled')
    save(ROOT / 'config.json', config)


def install():
    if AGENT.exists() or (ROOT / 'vpn_guard.py').exists():
        raise RuntimeError('Already installed. Use the existing controls; uninstall before replacing code.')
    ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(ROOT, 0o700)
    configure()
    script = ROOT / 'vpn_guard.py'
    shutil.copyfile(Path(__file__).resolve(), script)
    AGENT.parent.mkdir(parents=True, exist_ok=True)
    data = dict(Label=LABEL, ProgramArguments=[sys.executable, str(script), 'watch'],
                RunAtLoad=True, KeepAlive=True, ThrottleInterval=5, ProcessType='Background')
    with AGENT.open('wb') as stream:
        plistlib.dump(data, stream)
    os.chmod(AGENT, 0o600)
    started = time.time()
    run(['/bin/launchctl', 'bootstrap', 'gui/' + str(os.getuid()), str(AGENT)], timeout=10)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        status = load(ROOT / 'status.json', {})
        if status.get('time', 0) >= started:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError('LaunchAgent installed, but no fresh watcher heartbeat. Use uninstall and check the launchctl status in README.')
    print('Installed for this macOS user. Use status.command to verify a fresh heartbeat.')


def uninstall():
    if AGENT.exists():
        domain = 'gui/' + str(os.getuid())
        present = subprocess.run(['/bin/launchctl', 'print', domain + '/' + LABEL],
                                 capture_output=True, timeout=5)
        if present.returncode == 0:
            run(['/bin/launchctl', 'bootout', domain, str(AGENT)], timeout=10)
        AGENT.unlink()
    with lock(ROOT):
        Controller().step([], True)
        # Preserve config and status for diagnosis. No recursive deletion.
        (ROOT / 'vpn_guard.py').unlink(missing_ok=True)
        save(ROOT / 'status.json', dict(time=time.time(), healthy=False, reason='UNINSTALLED: watcher disabled', paused=0))
    print('Watcher disabled; its surviving paused processes resumed. Local config retained.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['install','watch','status','resume','uninstall'])
    command = parser.parse_args().command
    if sys.platform != 'darwin':
        parser.error('Only macOS is supported. Tests can run on other platforms.')
    if os.getuid() == 0:
        parser.error('Run as your normal macOS user, without sudo.')
    if command == 'install':
        install()
    elif command == 'watch':
        watch()
    elif command == 'uninstall':
        uninstall()
    elif command == 'resume':
        with lock(ROOT):
            Controller().step([], True)
        print('Recorded processes resumed. This does not enable protection.')
    else:
        status = load(ROOT / 'status.json', {})
        status['heartbeat_fresh'] = 0 <= time.time() - status.get('time', 0) < 5
        print(json.dumps(status, ensure_ascii=False, indent=2))
        if not status['heartbeat_fresh'] or not status.get('healthy'):
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
