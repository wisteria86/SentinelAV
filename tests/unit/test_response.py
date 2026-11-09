# Purpose: Verify test response behavior using controlled fixtures.
# Works with: data.storage, detection.engine, paths, response.response
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from sentinelav.detection.engine import Scanner
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService, dpapi, checked_path

ROOT = RESOURCE_ROOT
MARKER = b'SENTINELAV_DEMO_THREAT_7C23A'


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root/'state'/'test.db')
        self.service = ResponseService(self.store,ROOT)
        self.file = self.root/'harmless.txt'
        self.file.write_bytes(MARKER)
        self.detection = dict(path=str(self.file.resolve()),sha256=hashlib.sha256(MARKER).hexdigest(),reasons=['Demo'])

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def test_dpapi_roundtrip(self):
        protected = dpapi(MARKER)
        self.assertNotIn(MARKER,protected)
        self.assertEqual(dpapi(protected,True),MARKER)

    def test_derived_content_detection_survives_fresh_quarantine_verification(self):
        import base64
        self.file=self.file.with_suffix('.ps1')
        self.file.write_bytes(base64.b64encode(MARKER))
        self.store.set('inspection_options',{'advanced':True,'documents':False})
        scanner=Scanner(ROOT/'signatures.json',ROOT/'rules',options={'advanced':True,'documents':False})
        try:
            report=scanner.scan([self.file],lambda:False,lambda *args:None)
            detection=next(d for d in report['detections'] if d.get('detection_scope')=='derived content')
        finally: scanner.signatures.close()
        record=self.service.quarantine_file(detection)
        self.assertFalse(self.file.exists())
        self.service.restore(record['id'],self.file)
        self.assertEqual(self.file.read_bytes(),base64.b64encode(MARKER))

    def test_quarantine_restore_no_overwrite_and_audit(self):
        record = self.service.quarantine_file(self.detection)
        self.assertFalse(self.file.exists())
        blob = self.service.vault/(record['id']+'.sav')
        self.assertNotIn(MARKER,blob.read_bytes())
        self.file.write_bytes(b'existing file')
        with self.assertRaises(FileExistsError):
            self.service.restore(record['id'],self.file)
        self.assertEqual(self.file.read_bytes(),b'existing file')
        target = self.root/'restored.txt'
        self.service.restore(record['id'],target)
        self.assertEqual(target.read_bytes(),MARKER)
        self.assertFalse(blob.exists())
        self.assertEqual(self.store.quarantine()[0]['state'],'Restored')
        self.assertTrue(any(e['kind']=='File restored' for e in self.store.events()))

    def test_delete_and_tamper_refusal(self):
        record = self.service.quarantine_file(self.detection)
        blob = self.service.vault/(record['id']+'.sav')
        blob.write_bytes(b'tampered')
        with self.assertRaises(OSError):
            self.service.restore(record['id'],self.file)
        self.assertFalse(self.file.exists())
        self.service.delete(record['id'])
        self.assertFalse(blob.exists())
        self.assertEqual(self.store.quarantine()[0]['state'],'Deleted')

    def test_stale_detection_and_system_paths_refused(self):
        self.file.write_text('changed file')
        with self.assertRaises(ValueError):
            self.service.quarantine_file(self.detection)
        self.assertTrue(self.file.exists())
        with self.assertRaises(ValueError):
            checked_path(PROJECT_ROOT/'app.py')
        with self.assertRaises(ValueError):
            self.service.terminate(os.getpid(),0,self.detection)

    def test_hardlink_refused_without_removing_original(self):
        linked = self.root/'linked.txt'
        os.link(self.file,linked)
        with self.assertRaises(ValueError):
            self.service.quarantine_file(self.detection)
        self.assertTrue(self.file.exists())
        self.assertTrue(linked.exists())

    def test_hash_trust_exact_content_only(self):
        scanner = Scanner(ROOT/'signatures.json',ROOT/'rules',trusted_hashes=[self.detection['sha256']])
        result = scanner.scan([self.file],lambda:False,lambda *args:None)
        self.assertEqual(result['detections'],[])
        self.file.write_bytes(MARKER+b' modified')
        result = scanner.scan([self.file],lambda:False,lambda *args:None)
        self.assertEqual(len(result['detections']),1)

    def test_pid_reuse_refused_and_signature_required(self):
        process = Mock()
        process.create_time.return_value = 20
        with patch('sentinelav.response.response.psutil.Process',return_value=process):
            with self.assertRaises(ValueError):
                self.service.terminate(123456,10,self.detection)
        process.terminate.assert_not_called()
        self.file.write_text('ordinary text')
        with patch('sentinelav.response.response.psutil.Process') as process_class:
            with self.assertRaises(ValueError):
                self.service.terminate(123456,10,self.detection)
            process_class.assert_not_called()

    def test_interrupted_quarantine_and_restore_recovery(self):
        save = self.store.save_quarantine
        count = [0]
        def fail_after_removal(record):
            count[0] += 1
            if count[0]==2:
                raise RuntimeError('simulated metadata failure')
            save(record)
        with patch.object(self.store,'save_quarantine',side_effect=fail_after_removal):
            with self.assertRaises(RuntimeError):
                self.service.quarantine_file(self.detection)
        record = self.store.quarantine()[0]
        self.assertEqual(record['state'],'Preparing')
        self.assertFalse(self.file.exists())
        self.service.recover(record['id'])
        record = self.store.quarantine()[0]
        self.assertEqual(record['state'],'Quarantined')
        target = self.root/'interrupted-restore.txt'
        target.write_bytes(MARKER)
        record.update(state='Restore pending',restore_path=str(target))
        self.store.save_quarantine(record)
        result = self.service.recover(record['id'])
        self.assertEqual(result['state'],'Restored')
        self.assertEqual(target.read_bytes(),MARKER)

    def test_termination_guard_and_audit_without_killing_a_process(self):
        process = Mock()
        process.create_time.return_value = 10
        process.exe.return_value = str(self.file)
        process.username.return_value = 'test-owner'
        current = Mock()
        current.parents.return_value = []
        current.username.return_value = 'test-owner'
        with patch('sentinelav.response.response.psutil.Process',side_effect=lambda pid=None:current if pid is None else process), patch('sentinelav.response.response.is_critical_process',return_value=True):
            with self.assertRaises(ValueError):
                self.service.terminate(123456,10,self.detection)
            process.terminate.assert_not_called()
        with patch('sentinelav.response.response.psutil.Process',side_effect=lambda pid=None:current if pid is None else process), patch('sentinelav.response.response.is_critical_process',return_value=False):
            result = self.service.terminate(123456,10,self.detection)
        process.terminate.assert_called_once()
        self.assertEqual(result['state'],'Terminated')
        self.assertTrue(any(e['kind']=='Process terminated' for e in self.store.events()))

    def test_restore_holds_exclusive_destination_until_backup_cleanup(self):
        record=self.service.quarantine_file(self.detection)
        blob=self.service.vault/(record['id']+'.sav')
        target=self.root/'exclusive-restore.txt'
        unlink=Path.unlink
        attempts=[]
        def intercept(path,*args,**kwargs):
            if path==blob:
                with self.assertRaises(PermissionError):
                    with target.open('wb') as stream:
                        stream.write(b'concurrent modification')
                attempts.append(True)
            return unlink(path,*args,**kwargs)
        with patch.object(Path,'unlink',autospec=True,side_effect=intercept):
            self.service.restore(record['id'],target)
        self.assertEqual(attempts,[True])
        self.assertEqual(target.read_bytes(),MARKER)


if __name__=='__main__':
    unittest.main()
