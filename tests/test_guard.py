import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
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
