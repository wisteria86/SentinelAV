# Purpose: Prevent lost telemetry and reused PIDs from masquerading as reliable coverage.
# Works with: monitoring.health; monitoring.monitoring

import unittest
from types import SimpleNamespace
from unittest.mock import patch
import psutil
from sentinelav.monitoring.health import MonitoringHealth, verified_network_processes


class MonitoringHealthTests(unittest.TestCase):
    def test_loss_survives_queue_drain_and_collector_disposal(self):
        health = MonitoringHealth()
        health.lost('Filesystem', 3)
        health.lost('Filesystem', 0)
        health.lost('ETW', 5, cumulative=True)
        health.lost('ETW', 2, cumulative=True)
        health.unavailable('ETW', 'collector exited')
        state = health.status()
        self.assertEqual(state['telemetry_losses'], {'Filesystem': 3, 'ETW': 5})
        self.assertIn('collector exited', state['telemetry_error'])
        self.assertEqual(MonitoringHealth().status()['telemetry_error'], '')

    def test_reused_exited_unknown_and_excluded_pids_are_not_attributed(self):
        connections = [SimpleNamespace(pid=i, status='ESTABLISHED', raddr=('192.0.2.1', 443)) for i in range(1, 6)]
        snapshot = {i: dict(pid=i, create_time=100, exe=f'app{i}') for i in range(1, 5)}
        def process(pid):
            if pid == 3:
                raise psutil.NoSuchProcess(pid)
            return SimpleNamespace(create_time=lambda: 200 if pid == 2 else 100)
        with patch('sentinelav.monitoring.health.psutil.Process', side_effect=process):
            verified, omitted = verified_network_processes(connections, snapshot, [], lambda p, _: p == 'app4')
        self.assertEqual(set(verified), {1})
        self.assertEqual(omitted, 3)
