# Purpose: Verify test background behavior using controlled fixtures.
# Works with: data.storage, monitoring.background, paths, ui.helpers.background_ui
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import json
from pathlib import Path
import tempfile
import unittest
import threading
import time
from unittest.mock import patch
from PySide6.QtCore import QCoreApplication
from sentinelav.monitoring.background import (
    decode,
    endpoint,
    configuration,
    MAX_MESSAGE,
    EngineHost,
)
from sentinelav.data.storage import Store


class BackgroundProtocolTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name == 'nt', 'Windows token checks')
    def test_elevated_engine_still_refuses_to_write_user_configuration(self):
        from sentinelav.monitoring.background import main

        with (
            patch('ctypes.windll.shell32.IsUserAnAdmin', return_value=1),
            patch('pathlib.Path.mkdir') as mkdir,
        ):
            with self.assertRaisesRegex(RuntimeError, 'without administrator elevation'):
                main(Path('unused'))
            mkdir.assert_not_called()

    @unittest.skipUnless(__import__('os').name == 'nt', 'Windows engine startup')
    def test_startup_failure_has_nonmodal_diagnostic_and_releases_lock(self):
        from sentinelav.monitoring.background import main

        with (
            tempfile.TemporaryDirectory() as d,
            patch('ctypes.windll.shell32.IsUserAnAdmin', return_value=0),
            patch('sentinelav.monitoring.background.QCoreApplication'),
            patch('sentinelav.monitoring.background.QLockFile') as lock,
            patch(
                'sentinelav.monitoring.background.EngineHost',
                side_effect=RuntimeError('fixture startup failure'),
            ),
        ):
            lock.return_value.tryLock.return_value = True
            self.assertEqual(main(Path(d)), 1)
            self.assertEqual(
                json.loads((Path(d) / 'engine-startup-error.json').read_text())['reason'],
                'fixture startup failure',
            )
            lock.return_value.unlock.assert_called_once()

    def test_native_collector_setting_reaches_background_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'state/test.db')
            try:
                store.set(
                    'kernel_collector',
                    'C:/Program Files/SentinelAVTelemetry/SentinelAV.Telemetry.exe',
                )
                config = configuration(store, RESOURCE_ROOT)
                self.assertEqual(
                    config['kernel_collector'],
                    'C:/Program Files/SentinelAVTelemetry/SentinelAV.Telemetry.exe',
                )
            finally:
                store.db.close()

    def test_rejects_arbitrary_commands_payloads_and_wrong_types(self):
        for payload in [
            [],
            {},
            {'version': True, 'command': 'start'},
            {'version': 1, 'command': ['start']},
            {'version': 1, 'command': 'execute'},
            {'version': 1, 'command': 'start', 'path': 'anything.exe'},
            {'version': 1, 'command': 'poll', 'cursor': -1},
            {'version': 1, 'command': 'poll', 'cursor': True},
            {'version': 1, 'command': 'poll', 'epoch': 'x' * 65},
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                decode(json.dumps(payload).encode())
        with self.assertRaises(ValueError):
            decode(b' ' * (MAX_MESSAGE + 1))

    def test_versioned_allowlist(self):
        for command in ('status', 'start', 'stop', 'shutdown', 'poll'):
            self.assertEqual(
                decode(json.dumps(dict(version=1, command=command)).encode())['command'], command
            )

    def test_endpoint_is_stable_and_separates_data_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(endpoint(temp), endpoint(Path(temp) / '.'))
            self.assertNotEqual(endpoint(temp), endpoint(Path(temp) / 'other'))

    def test_engine_owns_resource_paths_and_validates_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = Store(root / 'state' / 'test.db')
            try:
                store.set('signatures', 'attacker-controlled.json')
                config = configuration(store, root)
                self.assertEqual(config['signatures'], root / 'signatures.json')
                self.assertIn(str(store.path.parent), config['exclusions'])
                store.set('max_mb', True)
                with self.assertRaises(ValueError):
                    configuration(store, root)
                store.set('max_mb', 100)
                store.set('watch_folders', ['relative-folder'])
                with self.assertRaises(ValueError):
                    configuration(store, root)
                store.set('watch_folders', [])
                store.set('watch_network', 'yes')
                with self.assertRaises(ValueError):
                    configuration(store, root)
            finally:
                store.db.close()


class EngineLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def test_duplicate_start_stop_and_failure_are_visible(self):
        class FixtureMonitor:
            count = 0

            def __init__(self, config, emit, status):
                type(self).count += 1
                self.stop = threading.Event()
                self.emit = emit
                self.status = status

            def run(self):
                self.status(dict(folders=0))
                self.stop.wait(2)

        with tempfile.TemporaryDirectory() as temp:
            host = EngineHost(temp, RESOURCE_ROOT, FixtureMonitor)
            try:
                host.start()
                host.start()
                self.assertEqual(FixtureMonitor.count, 1)
                host.thread.join(0.02)
                host.tick()
                self.assertEqual(host.state, 'Active')
                host.stop()
                host.thread.join(2)
                host.tick()
                self.assertEqual(host.state, 'Off')
                host.publish('error', 'Fixture source failed')
                host.tick()
                self.assertEqual(host.state, 'Failed')
                self.assertEqual(
                    host.handle(dict(command='status'))['error'], 'Fixture source failed'
                )
            finally:
                host.stop()
                if host.thread:
                    host.thread.join(3)
                host.server.close()
                host.timer.stop()
                host.store.db.close()

    def test_replay_gaps_and_response_paging(self):
        with tempfile.TemporaryDirectory() as temp:
            host = EngineHost(temp, RESOURCE_ROOT)
            try:
                for n in range(205):
                    host.events.append((n + 1, dict(details='x' * 1000, level='Info')))
                host.sequence = 205
                reply = host.handle(dict(command='poll', epoch=host.epoch, cursor=0))
                self.assertTrue(reply['gap'])
                self.assertLess(reply['cursor'], 205)
                self.assertLess(len(json.dumps(reply).encode()), MAX_MESSAGE)
                next_reply = host.handle(
                    dict(command='poll', epoch=host.epoch, cursor=reply['cursor'])
                )
                self.assertFalse(next_reply['gap'])
                self.assertGreater(next_reply['cursor'], reply['cursor'])
            finally:
                host.server.close()
                host.timer.stop()
                host.store.db.close()

    def test_worker_surfaces_disconnection(self):
        from sentinelav.ui.helpers.background_ui import BackgroundWorker

        worker = BackgroundWorker(Path('unused'), attach_only=True)
        errors = []
        worker.failed.connect(errors.append)
        with patch(
            'sentinelav.ui.helpers.background_ui.request',
            side_effect=[
                dict(state='Active', epoch='fixture', cursor=0),
                ConnectionError('fixture disconnect'),
            ],
        ):
            worker.run()
        self.assertEqual(len(errors), 1)
        self.assertIn('status is unknown', errors[0])


if __name__ == '__main__':
    unittest.main()
