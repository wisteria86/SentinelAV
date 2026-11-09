# Purpose: Verify test lab behavior using controlled fixtures.
# Works with: data.storage, lab.lab, paths
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelav.lab.lab import SimulationRunner,PROFILES,capabilities
from sentinelav.data.storage import Store

ROOT=RESOURCE_ROOT


class LabTests(unittest.TestCase):
    def test_all_profiles_clean_up_and_never_launch_or_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            user_file=base/'untouched.txt'
            user_file.write_text('preserve this user fixture')
            with patch('subprocess.run',side_effect=AssertionError('No subprocess allowed in simulation')),patch('socket.create_connection',side_effect=AssertionError('No connections allowed')):
                run=SimulationRunner(ROOT,base/'lab').run(list(PROFILES))
            self.assertEqual(run['status'],'Checks passed')
            self.assertTrue(run['workspace_reset'])
            self.assertFalse(run['isolated'])
            self.assertFalse(run['guest_executed'])
            self.assertEqual(len(run['results']),4)
            self.assertEqual(list((base/'lab').iterdir()),[])
            self.assertEqual(user_file.read_text(),'preserve this user fixture')

    def test_unknown_profile_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace=Path(temp)/'never-created'
            with self.assertRaises(ValueError):
                SimulationRunner(ROOT,workspace).run(['custom-command'])
            self.assertFalse(workspace.exists())

    def test_cancel_cleans_only_own_temporary_run(self):
        with tempfile.TemporaryDirectory() as temp:
            stop=threading.Event()
            stop.set()
            run=SimulationRunner(ROOT,Path(temp)/'lab',stop=stop).run(['signature'])
            self.assertEqual(run['status'],'Cancelled')
            self.assertTrue(run['workspace_reset'])

    def test_lab_history_is_separate_from_scan_history(self):
        with tempfile.TemporaryDirectory() as temp:
            store=Store(Path(temp)/'state.db')
            run=SimulationRunner(ROOT,Path(temp)/'lab').run(['signature'])
            store.save_lab_run(run)
            self.assertEqual(store.lab_runs()[0]['id'],run['id'])
            self.assertEqual(store.history(),[])
            self.assertEqual(store.events(),[])
            store.db.close()

    def test_capability_failure_never_claims_vm_is_ready(self):
        with patch('sentinelav.lab.lab.subprocess.run',side_effect=PermissionError('not permitted')):
            result=capabilities()
        self.assertFalse(result['vm_configured'])
        self.assertIn('could not be verified',result['note'])

    def test_scan_deadline_cooperates_and_disposes_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            runner=SimulationRunner(ROOT,Path(temp)/'lab')
            def scan(roots,cancelled,progress):
                runner.started-=20
                self.assertTrue(cancelled())
                return dict(scanned=0,detections=[],errors=[])
            with patch('sentinelav.lab.lab.Scanner') as scanner:
                scanner.return_value.scan.side_effect=scan
                run=runner.run(['signature'])
            self.assertEqual(run['status'],'Failed')
            self.assertIn('15-second limit',run['error'])
            self.assertTrue(run['workspace_reset'])


if __name__=='__main__':
    unittest.main()
