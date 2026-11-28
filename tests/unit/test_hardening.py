# Purpose: Verify test hardening behavior using controlled fixtures.
# Works with: detection.engine, entrypoint, paths, platform.runtime
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import xml.etree.ElementTree as ET
from sentinelav.detection.engine import Scanner
from sentinelav.entrypoint import prepare_self_test_dir
from sentinelav.platform.runtime import (
    set_startup,
    register_schedule,
    task_xml,
    launch_command,
    owns_task,
)

ROOT = RESOURCE_ROOT


class HardeningTests(unittest.TestCase):
    def test_self_test_refuses_existing_directory_and_preserves_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / 'packaged-demo.txt'
            marker.write_text('user-owned content')
            with self.assertRaises(FileExistsError):
                prepare_self_test_dir(root)
            self.assertEqual(marker.read_text(), 'user-owned content')
            fresh = root / 'new'
            self.assertEqual(prepare_self_test_dir(fresh), fresh.absolute())

    def test_self_test_rejects_junction_components(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(Path, 'is_junction', return_value=True):
                with self.assertRaises(ValueError):
                    prepare_self_test_dir(Path(temp) / 'never-created')

    def test_foreign_startup_registration_is_never_replaced_or_deleted(self):
        with (
            patch('winreg.CreateKey'),
            patch(
                'winreg.QueryValueEx', return_value=('C:/AnotherCopy/SentinelAV.exe --startup', 1)
            ),
            patch('winreg.SetValueEx') as write,
            patch('winreg.DeleteValue') as delete,
        ):
            for enabled in [True, False]:
                with self.assertRaises(FileExistsError):
                    set_startup(enabled)
            write.assert_not_called()
            delete.assert_not_called()

    def test_task_ownership_includes_data_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp).resolve()
            task = ET.fromstring(task_xml(dict(next_run='2026-10-16T18:00:00+05:00'), data))
            self.assertTrue(owns_task(task, data))
            self.assertFalse(owns_task(task, data / 'other'))
            with (
                patch('sentinelav.platform.runtime.existing_task', return_value=task),
                patch('sentinelav.platform.runtime.subprocess.run') as run,
            ):
                for enabled in [True, False]:
                    with self.assertRaises(FileExistsError):
                        register_schedule(dict(enabled=enabled), data / 'other')
                run.assert_not_called()

    def test_owned_task_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp).resolve()
            task = ET.fromstring(task_xml(dict(next_run='2026-10-16T18:00:00+05:00'), data))
            with (
                patch('sentinelav.platform.runtime.existing_task', return_value=task),
                patch('sentinelav.platform.runtime.subprocess.run') as run,
            ):
                register_schedule(dict(enabled=False), data)
                self.assertIn('/Delete', run.call_args.args[0])

    def test_changing_file_is_omitted_with_error_not_reported_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'changing.txt'
            path.write_text('ordinary contents')
            stat = path.stat()
            after = SimpleNamespace(
                **{k: getattr(stat, k) for k in ['st_dev', 'st_ino', 'st_size', 'st_ctime_ns']},
                st_mtime_ns=stat.st_mtime_ns + 1,
            )
            scanner = Scanner(ROOT / 'signatures.json', ROOT / 'rules')
            with patch('sentinelav.detection.engine.os.fstat', side_effect=[stat, after]):
                result = scanner.scan([path], lambda: False, lambda *args: None)
            self.assertEqual(result['scanned'], 0)
            self.assertEqual(result['status'], 'Complete with omissions')
            self.assertIn('changed during inspection', result['errors'][0])


if __name__ == '__main__':
    unittest.main()
