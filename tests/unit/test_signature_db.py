# Purpose: Verify test signature db behavior using controlled fixtures.
# Works with: detection.engine, detection.signature_db, updates.hash_archive
# Used by: unittest discovery

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile,ZIP_DEFLATED
from sentinelav.detection.engine import Scanner
from sentinelav.detection.signature_db import SignatureIndex
from sentinelav.updates.hash_archive import import_archive


class SignatureDatabaseTests(unittest.TestCase):
    def archive(self,root,rows,name='feed.zip',member='full.csv'):
        path=root/name
        header='# "first_seen_utc","sha256_hash","signature","file_type_guess"\n'
        text=header+''.join(f'"2026-11-01", "{digest}", "{label}", "txt"\n' for digest,label in rows)
        with ZipFile(path,'w',ZIP_DEFLATED) as zipped:
            zipped.writestr(member,text)
        return path

    def test_actual_scanner_hash_detection_and_benign_control(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            marker=b'Harmless SQLite signature test fixture'
            digest=hashlib.sha256(marker).hexdigest()
            feed=self.archive(root,[(digest,'Fixture'),(digest,'OtherLabel')])
            metadata=import_archive(feed,root/'signature-data',True)
            self.assertEqual(metadata['unique_sha256'],1)
            self.assertEqual(metadata['duplicate_rows'],1)
            (root/'signatures.json').write_text('{}')
            (root/'fixture.txt').write_bytes(marker)
            (root/'benign.txt').write_text('Normal unrelated document')
            scanner=Scanner(root/'signatures.json',root/'rules')
            try:
                report=scanner.scan([root/'fixture.txt',root/'benign.txt'],lambda:False,lambda *a:None)
                self.assertEqual(len(report['detections']),1)
                self.assertIn('Fixture / OtherLabel',report['detections'][0]['reasons'][0])
                self.assertIn('Hash database:',report['detections'][0]['reasons'][0])
                self.assertNotIn('MalwareBazaar:',report['detections'][0]['reasons'][0])
                self.assertEqual(report['scanned'],2)
            finally: scanner.signatures.close()

    def test_old_readers_keep_snapshot_after_atomic_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'signatures.json').write_text('{}')
            first=self.archive(root,[('a'*64,'First')])
            import_archive(first,root/'signature-data',True)
            old=SignatureIndex(root/'signatures.json')
            try:
                second=self.archive(root,[('b'*64,'Second')],name='second.zip')
                import_archive(second,root/'signature-data',True)
                current=SignatureIndex(root/'signatures.json')
                try:
                    self.assertIn('a'*64,old)
                    self.assertNotIn('b'*64,old)
                    self.assertIn('b'*64,current)
                    self.assertNotIn('a'*64,current)
                finally: current.close()
                self.assertTrue(list((root/'signature-data').glob('previous-*.json')))
            finally: old.close()

    def test_invalid_import_preserves_active_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            valid=self.archive(root,[('a'*64,'Valid')])
            output=root/'signature-data'
            import_archive(valid,output,True)
            before=(output/'active.json').read_bytes()
            invalid=self.archive(root,[('bad','Invalid')],name='bad.zip')
            with self.assertRaises(ValueError): import_archive(invalid,output,True)
            self.assertEqual((output/'active.json').read_bytes(),before)
            self.assertEqual(len(list(output.glob('hashes-*.sqlite'))),1)

    def test_rejects_extra_members_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            archive=self.archive(root,[('a'*64,'Fixture')],member='../full.csv')
            with self.assertRaises(ValueError): import_archive(archive,root/'signature-data',True)
            self.assertFalse((root/'signature-data').exists())

    def test_json_overlay_and_manifest_path_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            digest='a'*64
            archive=self.archive(root,[(digest,'FeedLabel')])
            import_archive(archive,root/'signature-data',True)
            (root/'signatures.json').write_text(json.dumps({digest:'LocalOverride','b'*64:'LocalOnly'}))
            index=SignatureIndex(root/'signatures.json')
            try:
                self.assertEqual(index[digest],'LocalOverride')
                self.assertEqual(len(index),2)
            finally: index.close()
            (root/'signature-data'/'active.json').write_text(json.dumps(dict(schema=1,database='../escape.sqlite',unique_sha256=1)))
            with self.assertRaises(ValueError): SignatureIndex(root/'signatures.json')

    def test_malformed_quoted_filename_is_omitted_and_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            archive=self.archive(root,[('a'*64,'Valid')])
            with ZipFile(archive) as zipped: text=zipped.read('full.csv')
            with ZipFile(archive,'w',ZIP_DEFLATED) as zipped:
                zipped.writestr('full.csv',text+b'"bad"suffix, "ambiguous", "record", "ignored"\n')
            metadata=import_archive(archive,root/'signature-data',True)
            self.assertEqual(metadata['unique_sha256'],1)
            self.assertEqual(metadata['skipped_malformed_rows'],1)
            self.assertEqual(metadata['skipped_physical_lines'],[3])


if __name__=='__main__': unittest.main()
