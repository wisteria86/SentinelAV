# Purpose: Verify test windows service behavior using controlled fixtures.
# Works with: monitoring.monitoring, platform.windows_service
# Used by: unittest discovery

import ctypes
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import sentinelav.platform.windows_service as windows_service
import sentinelav.monitoring.monitoring as monitoring  # Load native watchdog bindings before mocking advapi32.


class NativeCall:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class ServiceHostTests(unittest.TestCase):
    def test_source_or_interactive_execution_is_refused(self):
        with patch('sentinelav.platform.windows_service.sys.frozen', False, create=True):
            with self.assertRaisesRegex(RuntimeError, 'packaged executable'):
                windows_service.run_service()

    def test_scm_lifecycle_uses_protected_policy_and_least_privilege_contract(self):
        self.exercise_scm(False)

    def test_opt_in_amsi_broker_health_and_shutdown(self):
        self.exercise_scm(True)

    def exercise_scm(self, broker_enabled):
        # Simulated SCM callbacks only: no Windows service is registered/started.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            install = root / 'ProgramFiles' / 'SentinelAVProtection'
            install.mkdir(parents=True)
            base = root / 'ProgramData' / 'SentinelAVProtection'
            data = base / 'data'
            data.mkdir(parents=True)
            watched = root / 'watched'
            watched.mkdir()
            (base / 'policy.json').write_text(
                json.dumps(
                    dict(
                        amsi_broker=broker_enabled,
                        folders=[str(watched)],
                        signatures='untrusted.json',
                        auto_response={'enabled': True},
                    )
                )
            )
            states = []
            recorded = {}

            def status(handle, pointer):
                values = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 7)).contents
                states.append(values[1])
                return 1

            def handler(name, callback, context):
                recorded['control'] = callback
                return 123

            def dispatch(table):
                table[0].main(0, None)
                return 1

            native = SimpleNamespace(
                RegisterServiceCtrlHandlerExW=NativeCall(handler),
                SetServiceStatus=NativeCall(status),
                StartServiceCtrlDispatcherW=NativeCall(dispatch),
            )

            class FixtureBroker:
                def __init__(self, resources):
                    recorded['broker'] = self
                    self.stop = threading.Event()
                    self.error = None
                    self.completed = 2
                    self.omissions = 1
                    self.thread = SimpleNamespace(is_alive=lambda: True)

                def start(self):
                    return self

                def close(self):
                    recorded['broker_closed'] = self.stop.is_set()

            class FixtureMonitor:
                def __init__(self, config, emit, callback):
                    recorded['config'] = config
                    self.stop = threading.Event()
                    self.callback = callback

                def run(self):
                    self.callback(dict(folders=1, checked=0))
                    recorded['control'](1, 0, None, None)
                    self.asserted_stop = self.stop.is_set()
                    recorded['stopped'] = self.asserted_stop

            with (
                patch('sentinelav.platform.windows_service.sys.frozen', True, create=True),
                patch(
                    'sentinelav.platform.windows_service.sys.executable',
                    str(install / 'SentinelAV.exe'),
                ),
                patch.dict(os.environ, {'ProgramFiles': str(root / 'ProgramFiles')}),
                patch(
                    'sentinelav.platform.windows_service.service_paths', return_value=(base, data)
                ),
                patch(
                    'sentinelav.platform.core.windows_identity.current_sid', return_value='S-1-5-19'
                ),
                patch('sentinelav.platform.windows_service.ctypes.WinDLL', return_value=native),
                patch(
                    'sentinelav.platform.core.integrity.verify_installation',
                    return_value={'status': 'Verified'},
                ),
                patch('sentinelav.platform.core.integrity.verify_windows_acl', return_value=True),
                patch('sentinelav.monitoring.monitoring.Monitor', FixtureMonitor),
                patch('sentinelav.platform.core.amsi_broker.AmsiBroker', FixtureBroker),
            ):
                self.assertEqual(windows_service.run_service(), 0)
            self.assertIn(2, states)
            self.assertIn(4, states)
            self.assertIn(3, states)
            self.assertEqual(states[-1], 1)
            self.assertTrue(recorded['stopped'])
            self.assertNotEqual(str(recorded['config']['signatures']), 'untrusted.json')
            self.assertFalse(recorded['config'].get('auto_response', {}).get('enabled', False))
            health = json.loads((data / 'status.json').read_text())
            self.assertFalse(health['automatic_response'])
            self.assertEqual(health['amsi_broker']['enabled'], broker_enabled)
            self.assertEqual(health['amsi_broker']['running'], broker_enabled)
            self.assertEqual('broker' in recorded, broker_enabled)
            if broker_enabled:
                self.assertTrue(recorded['broker_closed'])


if __name__ == '__main__':
    unittest.main()
