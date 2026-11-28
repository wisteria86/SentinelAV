# Purpose: Verify test behavior behavior using controlled fixtures.
# Works with: monitoring.core.behavior
# Used by: unittest discovery

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from sentinelav.monitoring.core.behavior import BehaviorEngine, create_canary


class BehaviorTests(unittest.TestCase):
    def engine(self, **kwargs):
        self.events = []
        self.now = 100
        return BehaviorEngine(self.events.append, clock=lambda: self.now, **kwargs)

    def test_scores_need_independent_indicators_and_expire(self):
        engine = self.engine()
        engine.indicator('entity', 'one', 70, 'First fact')
        self.assertEqual(self.events[-1]['level'], 'Warning')
        engine.indicator('entity', 'one', 70, 'Same fact again')
        self.assertEqual(len(self.events), 1)
        engine.indicator('entity', 'two', 20, 'Second fact')
        self.assertEqual(self.events[-1]['level'], 'Alert')
        self.assertEqual(self.events[-1]['score'], 90)
        self.assertEqual(len(self.events[-1]['indicators']), 2)
        self.now += 61
        engine.indicator('entity', 'three', 30, 'Later fact')
        self.assertEqual(self.events[-1]['level'], 'Warning')
        self.assertEqual(self.events[-1]['score'], 30)

    def test_canary_change_plus_burst_alert_and_exclusion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            canary = create_canary(root)
            engine = self.engine(canaries=[canary])
            engine.check_canaries([root], [])
            self.assertEqual(self.events, [])
            Path(canary['path']).write_text('Harmless test edit')
            engine.check_canaries([root], [])
            self.assertEqual(self.events[-1]['score'], 70)
            self.assertEqual(self.events[-1]['level'], 'Warning')
            for i in range(30):
                engine.file_event('modified', root / f'demo-{i}.txt', [root], [])
            self.assertEqual(self.events[-1]['score'], 100)
            self.assertEqual(self.events[-1]['level'], 'Alert')
            self.assertNotIn('pid', self.events[-1])
            engine = self.engine(canaries=[canary])
            engine.check_canaries([root], [root])
            for i in range(40):
                engine.file_event('modified', root / f'excluded-{i}', [root], [root])
            self.assertEqual(self.events, [])

    def test_repeated_single_file_is_not_burst_and_window_expires(self):
        engine = self.engine()
        root = Path.cwd().resolve()
        for _ in range(50):
            engine.file_event('modified', root / 'same.txt', [root], [])
        self.assertEqual(self.events, [])
        for i in range(29):
            self.now += 11
            engine.file_event('modified', root / f'{i}.txt', [root], [])
        self.assertEqual(self.events, [])

    def test_process_context_and_network_combination(self):
        engine = self.engine(networks=['192.0.2.1/32'])
        info = dict(
            pid=42,
            ppid=1,
            name='example.exe',
            exe='C:/Users/test/Downloads/example.exe',
            create_time=1,
            cmdline=[],
        )
        engine.process(info)
        self.assertEqual(self.events, [])
        connection = SimpleNamespace(
            pid=42, status='ESTABLISHED', raddr=SimpleNamespace(ip='192.0.2.1', port=443)
        )
        engine.network([connection], {42: info})
        self.assertEqual(self.events[-1]['score'], 95)
        self.assertEqual(self.events[-1]['level'], 'Alert')
        self.assertEqual(self.events[-1]['pid'], 42)
        # A reused PID must not inherit old executable evidence.
        self.now += 61
        info = dict(info, create_time=2, exe='C:/Program Files/example.exe')
        engine.network([connection], {42: info})
        self.assertEqual(self.events[-1]['score'], 70)
        self.assertEqual(self.events[-1]['level'], 'Warning')

    def test_encoded_office_child_and_normal_process(self):
        engine = self.engine()
        normal = dict(
            pid=1, create_time=1, name='notepad.exe', exe='C:/Windows/notepad.exe', cmdline=[]
        )
        engine.process(normal, 'explorer.exe')
        self.assertEqual(self.events, [])
        engine.process(
            dict(
                normal,
                pid=2,
                name='powershell.exe',
                exe='C:/Temp/powershell.exe',
                cmdline=['powershell.exe', '-enc', 'harmless-placeholder'],
            ),
            'winword.exe',
        )
        self.assertEqual(self.events[-1]['score'], 90)
        self.assertEqual(self.events[-1]['level'], 'Alert')

    def test_missing_canary_and_network_fanout_need_corroboration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            canary = create_canary(root)
            Path(canary['path']).unlink()
            engine = self.engine(canaries=[canary])
            engine.check_canaries([root], [])
            self.assertEqual(self.events[-1]['level'], 'Warning')
            self.assertIn('missing', self.events[-1]['details'])
            engine.check_canaries([root], [])
            self.assertEqual(len(self.events), 1)
        engine = self.engine()
        info = dict(pid=2, create_time=1, exe='C:/Program Files/demo.exe')
        connections = [
            SimpleNamespace(
                pid=2, status='ESTABLISHED', raddr=SimpleNamespace(ip=f'8.8.8.{i}', port=443)
            )
            for i in range(1, 21)
        ]
        engine.network(connections, {2: info})
        self.assertEqual(self.events[-1]['score'], 45)
        self.assertEqual(self.events[-1]['level'], 'Warning')
        engine.indicator('process:2:1', 'user_location', 25, 'Temporary executable')
        self.assertEqual(self.events[-1]['score'], 70)
        self.assertEqual(self.events[-1]['level'], 'Alert')


if __name__ == '__main__':
    unittest.main()
