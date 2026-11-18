import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import shutil
import shlex
import uuid
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('guard', Path(__file__).parents[1] / 'vpn_guard.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
if sys.platform == 'win32':
    # Signals are simulated on Windows. Only the macOS integration test uses real signals.
    signal = SimpleNamespace(SIGSTOP=17, SIGCONT=19)
    g.signal = signal


def item(pid, path='/Applications/Claude.app/Contents/MacOS/Claude', parent=1, stopped=False):
    return dict(pid=pid, ppid=parent, uid=501, start='Tue Nov 17 10:00:00 2026', path=path, stopped=stopped)


class GuardTest(unittest.TestCase):
    def test_app_prefix_does_not_match_similarly_named_application(self):
        self.assertTrue(g.matched('/Applications/Claude.app/Contents/MacOS/Claude', ['/Applications/Claude.app']))
        self.assertFalse(g.matched('/Applications/Claude.app.evil/Contents/MacOS/Claude', ['/Applications/Claude.app']))

    def test_physical_and_unknown_interfaces_are_rejected(self):
        for name in ('en0', 'lo0', 'utun', 'utun4;evil', None):
            self.assertFalse(g.tunnel(name))
        self.assertTrue(g.tunnel('utun12'))

    def test_bad_ip_config_is_rejected(self):
        with self.assertRaises(ValueError):
            g.validate(dict(expected_ipv4='127.0.0.1', paths=[]))

    def test_node_launcher_is_not_a_native_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'codex'
            target.write_text('#!/usr/bin/env node\n')
            self.assertFalse(g.native(target))
            with self.assertRaises(ValueError):
                g.validate(dict(expected_ipv4='1.1.1.1', paths=[str(target)]))

    def test_only_target_tree_selected(self):
        table = {101: item(101), 102: item(102, '/native/child', 101),
                 103: item(103, '/native/grandchild', 102), 104: item(104, '/unrelated')}
        self.assertEqual(g.selected(table, ['/Applications/Claude.app'], {}), {101,102,103})

    def test_pid_reuse_is_not_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            g.save(directory/'paused.json', {'101':item(101)})
            changed = item(101); changed['start'] = 'another start'
            sent = []
            control = g.Controller(directory, lambda:{101:changed}, lambda *args:sent.append(args))
            control.step([], True)
            self.assertEqual(sent, [])
            self.assertEqual(control.paused, {})

    def test_stop_then_recover_only_our_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            table = {101:item(101),102:item(102,stopped=True)}
            sent = []
            control = g.Controller(Path(directory), lambda:table, lambda *args:sent.append(args))
            control.step(['/Applications/Claude.app'], False)
            self.assertEqual(sent, [(101,signal.SIGSTOP)])
            control = g.Controller(Path(directory), lambda:table, lambda *args:sent.append(args))
            control.step([], True)
            self.assertEqual(sent[-1], (101,signal.SIGCONT))
            self.assertNotIn((102,signal.SIGCONT), sent)

    def test_fail_to_signal_keeps_recovery_record(self):
        with tempfile.TemporaryDirectory() as directory:
            def denied(*args): raise PermissionError('denied')
            control = g.Controller(Path(directory), lambda:{101:item(101)}, denied)
            with self.assertRaises(PermissionError):
                control.step(['/Applications/Claude.app'], False)
            self.assertIn('101', g.load(Path(directory)/'paused.json'))

    def test_changed_identity_is_not_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshots = iter([{101:item(101)}, {101:item(101, '/unrelated')}])
            sent=[]
            control=g.Controller(Path(directory), lambda:next(snapshots), lambda *args:sent.append(args))
            control.step(['/Applications/Claude.app'], False)
            self.assertEqual(sent, [])

    def test_ipv6_bypass_blocks_without_even_probing_ip(self):
        with patch.object(g, 'route', side_effect=['utun2','en0']), patch.object(g,'public_ip') as probe:
            self.assertFalse(g.check_network({'expected_ipv4':'1.1.1.1'})[0])
            probe.assert_not_called()

    def test_ip_change_blocks(self):
        with patch.object(g, 'route', side_effect=['utun2',None]), patch.object(g,'public_ip', return_value='8.8.8.8'):
            self.assertFalse(g.check_network({'expected_ipv4':'1.1.1.1'})[0])

    def test_healthy_network_and_route_change(self):
        for routes, healthy in [(['utun2',None,'utun2',None],True), (['utun2',None,'en0',None],False)]:
            with patch.object(g,'route',side_effect=routes), patch.object(g,'public_ip',return_value='1.1.1.1'):
                self.assertEqual(g.check_network({'expected_ipv4':'1.1.1.1'})[0],healthy)

    def test_work_session_starts_recovers_and_ends(self):
        cases = (
            (False, None, None, 'waiting'),   # First watcher tick after login.
            (False, False, None, 'waiting'),  # No VPN to protect yet.
            (False, True, None, 'waiting'),   # A tunnel alone is not enough.
            (True, True, None, 'active'),
            (False, False, None, 'active'),   # A sudden drop preserves protection.
            (True, True, None, 'active'),
            (True, True, 'end', 'ended'),
            (False, None, None, 'ended'),     # Unknown network cannot end the suppression.
            (False, True, None, 'ended'),    # Changed IP cannot rearm an ended session.
            (True, True, None, 'ended'),
            (False, False, None, 'waiting'),
            (True, True, None, 'active'),
            (False, False, 'end', 'waiting'), # Explicit release after a disconnect.
            (True, True, None, 'active'),
            (True, True, 'end', 'ended'),
            (True, True, 'begin', 'active'),
        )
        mode = 'waiting'
        for healthy, tunnel_present, command, expected in cases:
            mode = g.next_session_mode(mode, healthy, tunnel_present, command)
            self.assertEqual(mode, expected)

    def test_watcher_restart_preserves_session_only_in_same_boot(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(g, 'ROOT', Path(directory)):
            for mode in ('active', 'ended'):
                g.save(g.ROOT / 'session.json', dict(boot='boot-one', mode=mode, command_id='applied'))
                self.assertEqual(g.read_session('boot-one')['mode'], mode)
                fresh = g.read_session('boot-two')
                self.assertEqual(fresh['mode'], 'waiting')
                self.assertIsNone(fresh['command_id'])

    def test_uninstall_after_manual_bootout(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            agent=directory/'test.plist'; agent.write_text('fixture')
            script=directory/'vpn_guard.py'; script.write_text('fixture')
            with patch.object(g,'ROOT',directory), patch.object(g,'AGENT',agent), \
                 patch.object(g.os,'getuid',return_value=501,create=True), \
                 patch.object(g.subprocess,'run',return_value=SimpleNamespace(returncode=3)), \
                 patch.object(g,'lock'), patch.object(g,'Controller') as controller:
                g.uninstall()
                controller.return_value.step.assert_called_once_with([],True)
                self.assertFalse(agent.exists())
                self.assertFalse(script.exists())
                self.assertFalse(g.load(directory/'status.json')['healthy'])

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS integration test')
    def test_launchagent_install_watch_and_uninstall(self):
        import time
        # Isolated HOME, unique executable and unique launchd label. No VPN is changed.
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve()
            root=home/'Library/Application Support/VPN Guard'
            agent=home/'Library/LaunchAgents/test.plist'
            label='org.vpnguard.test.'+uuid.uuid4().hex
            sleeper=home/'isolated-sleep'
            shutil.copyfile('/bin/sleep',sleeper); sleeper.chmod(0o700)
            process=subprocess.Popen([str(sleeper),'60'])
            network = root / 'test-network.json'
            g.save(network, {'up': False})
            harness = home / 'watch-with-fixture-network.py'
            harness.write_text('''
import importlib.util
import sys
from pathlib import Path

script, *args = sys.argv[1:]
spec = importlib.util.spec_from_file_location('vpn_guard', script)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
network = Path(script).parent / 'test-network.json'
guard.route = lambda family: ('utun7' if guard.load(network)['up'] else 'en0') if family == 4 else None
guard.public_ip = lambda *args: '1.1.1.1'
sys.argv = [script, *args]
guard.main()
''', encoding='utf-8')
            wrapper=home/'python-with-private-home'
            wrapper.write_text('#!/bin/sh\nexec /usr/bin/env HOME='+shlex.quote(str(home))+' '+shlex.quote(sys.executable)+' '+shlex.quote(str(harness))+' "$@"\n')
            wrapper.chmod(0o700)
            def configure():
                g.save(root/'config.json',dict(expected_ipv4='1.1.1.1',expected_ipv6=None,paths=[str(sleeper)]))
            def wait_status(mode, healthy, stopped):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    status = g.load(root / 'status.json', {})
                    current = g.processes().get(process.pid)
                    if (current and current['stopped'] == stopped and status.get('mode') == mode
                            and status.get('healthy') == healthy and g.heartbeat_fresh(status)):
                        return
                    time.sleep(0.2)
                detail = subprocess.run(['/bin/launchctl','print','gui/'+str(os.getuid())+'/'+label],capture_output=True,text=True).stdout
                self.fail(f'Expected {mode=} {healthy=} {stopped=}, got {status=} {current=} {detail=}')
            try:
                with patch.object(g,'ROOT',root), patch.object(g,'AGENT',agent), \
                     patch.object(g,'LABEL',label), patch.object(g,'configure',side_effect=configure), \
                     patch.object(g.sys,'executable',str(wrapper)):
                    g.install()
                    wait_status('waiting', False, False)
                    g.save(network, {'up': True})
                    wait_status('active', True, False)
                    g.save(network, {'up': False})
                    wait_status('active', False, True)
                    g.save(network, {'up': True})
                    wait_status('active', True, False)
                    g.request_session('end')
                    wait_status('ended', True, False)
                    g.save(network, {'up': False})
                    wait_status('waiting', False, False)
                    g.save(network, {'up': True})
                    wait_status('active', True, False)
                    g.save(network, {'up': False})
                    wait_status('active', False, True)
                    g.request_session('end')
                    wait_status('waiting', False, False)
                    g.uninstall()
                    time.sleep(0.2)
                    self.assertFalse(g.processes()[process.pid]['stopped'])
                    self.assertFalse(agent.exists())
            finally:
                subprocess.run(['/bin/launchctl','bootout','gui/'+str(os.getuid())+'/'+label],capture_output=True)
                os.kill(process.pid,signal.SIGCONT)
                process.terminate(); process.wait(timeout=5)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS integration test')
    def test_real_process_pause_recovery_and_libproc(self):
        # Only this test's own /bin/sleep PID is ever handed to the controller.
        import time
        process = subprocess.Popen(['/bin/sleep','60'])
        try:
            with tempfile.TemporaryDirectory() as directory:
                def snapshot():
                    current = g.processes()
                    return {process.pid:current[process.pid]} if process.pid in current else {}
                before=snapshot()
                self.assertIn(process.pid,before)
                target=before[process.pid]['path']
                control=g.Controller(Path(directory),snapshot)
                control.step([target],False)
                time.sleep(0.2)
                self.assertTrue(snapshot()[process.pid]['stopped'])
                control=g.Controller(Path(directory),snapshot)
                control.step([],True)
                time.sleep(0.2)
                self.assertFalse(snapshot()[process.pid]['stopped'])
        finally:
            os.kill(process.pid,signal.SIGCONT)
            process.terminate(); process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
