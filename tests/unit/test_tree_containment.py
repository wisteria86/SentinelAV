# Purpose: Verify test tree containment behavior using controlled fixtures.
# Works with: response.containment
# Used by: unittest discovery

import time
import unittest
from unittest.mock import Mock, patch
from sentinelav.response.containment import execute_plan


class TreeContainmentTests(unittest.TestCase):
    def setup_plan(self):
        root = Mock(pid=10)
        root.create_time.return_value = 1
        root.ppid.return_value = 0
        child = Mock(pid=20)
        child.create_time.return_value = 2
        child.ppid.return_value = 10
        root.children.return_value = [child]
        items = [
            dict(pid=10, creation=1, sha256='a' * 64, path='C:/root.exe'),
            dict(pid=20, creation=2, sha256='b' * 64, path='C:/child.exe'),
        ]
        return (
            root,
            child,
            dict(root_pid=10, root_creation=1, expires_at=time.time() + 60, processes=items),
        )

    def test_reversed_input_is_still_acted_on_child_first(self):
        root, child, plan = self.setup_plan()
        service = Mock()
        service.terminate.side_effect = lambda pid, *args: dict(pid=pid, state='Terminated')
        with patch('sentinelav.response.containment.psutil.Process', return_value=root):
            report = execute_plan(service, plan, ['a' * 64, 'b' * 64])
        self.assertEqual([call.args[0] for call in service.terminate.call_args_list], [20, 10])
        self.assertTrue(report['complete'])

    def test_pid_reuse_or_expiry_prevents_every_action(self):
        for scenario in ('reuse', 'expiry'):
            with self.subTest(scenario=scenario):
                root, child, plan = self.setup_plan()
                service = Mock()
                if scenario == 'reuse':
                    child.create_time.return_value = 3
                else:
                    plan['expires_at'] = time.time() - 1
                with patch('sentinelav.response.containment.psutil.Process', return_value=root):
                    with self.assertRaises(ValueError):
                        execute_plan(service, plan, ['a' * 64, 'b' * 64])
                service.terminate.assert_not_called()

    def test_unapproved_process_is_not_terminated(self):
        root, child, plan = self.setup_plan()
        service = Mock()
        service.terminate.side_effect = lambda pid, *args: dict(pid=pid, state='Terminated')
        with patch('sentinelav.response.containment.psutil.Process', return_value=root):
            report = execute_plan(service, plan, ['b' * 64])
        self.assertEqual([call.args[0] for call in service.terminate.call_args_list], [20])
        self.assertFalse(report['complete'])
