# Purpose: Verify test yara rules behavior using controlled fixtures.
# Works with: detection.engine, detection.yara_rules, paths
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import struct
from unittest.mock import Mock
from sentinelav.detection.engine import Scanner
from sentinelav.detection.yara_rules import compile_rules,RuleValidationError

ROOT=RESOURCE_ROOT


class YaraRuleTests(unittest.TestCase):
    def test_vmzeus_candidate_requires_header_gates_and_retains_attribution(self):
        rules,_,metadata=compile_rules(ROOT/'rules')
        # Inert instruction bytes with a deliberately incomplete file header;
        # this fixture is not an executable and is never launched.
        data=bytearray(512)
        fragment=bytes.fromhex('75086a0458e90000000032c06a4c8d7c242c59f3aa')
        data[256:256+len(fragment)]=fragment
        self.assertFalse(any(m.rule=='win_vmzeus_auto' for m in rules.match(data=bytes(data))))
        data[:2]=b'MZ'
        self.assertFalse(any(m.rule=='win_vmzeus_auto' for m in rules.match(data=bytes(data))))
        struct.pack_into('<I',data,0x3c,128)
        data[128:132]=b'PE\0\0'
        self.assertTrue(any(m.rule=='win_vmzeus_auto' for m in rules.match(data=bytes(data))))
        item=metadata['malpedia_vmzeus']
        self.assertEqual(item['license'],'CC-BY-SA-4.0')
        self.assertIn('gates added',item['changes'])

    def test_managed_subset_compiles_with_pinned_license_and_expected_counts(self):
        _,summary,metadata=compile_rules(ROOT/'rules')
        self.assertEqual(summary['research_rules'],15)
        self.assertEqual(summary['private_helpers'],2)
        self.assertEqual(summary['demo_rules'],1)
        self.assertEqual(summary['warnings'],[])
        self.assertEqual(summary['local_rules'],0)
        for item in metadata.values():
            if not item.get('demo'):
                self.assertIn(item['license'],('BSD-2-Clause','MIT','CC-BY-SA-4.0'))
                self.assertEqual(len(item['source_revision']),40)
                self.assertTrue((ROOT/'rules'/item['license_file']).is_file())

    def test_nonexecutable_string_fixture_matches_with_provenance(self):
        # Two-byte MZ marker plus strings only, not a valid executable or malware.
        headers=['RedLine | Log In','RedLine | Autofilles Viewer','RedLine | Choose Browser',
                 'RedLine | Cookie Viewer','RedLine | Credit Card Viewer','RedLine | Files Viewer']
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'signatures.json').write_text('{}')
            fixture=root/'nonexecutable-string-fixture.txt'
            fixture.write_bytes(b'MZ'+b'\0'*64+'\0'.join(headers).encode())
            scanner=Scanner(root/'signatures.json',ROOT/'rules')
            try:
                report=scanner.scan([fixture],lambda:False,lambda *a:None)
                self.assertEqual(len(report['detections']),1)
                finding=report['detections'][0]['yara_matches'][0]
                self.assertEqual(finding['rule'],'cw_Windows_Redline_panel_tab_headers')
                self.assertEqual(finding['license'],'BSD-2-Clause')
                self.assertFalse(finding['demo'])
                self.assertEqual(finding['effectiveness_evaluation'],'Deferred')
                self.assertIn('/blob/59745502656e813f9f79fc8005243edbc04f9397/',finding['source'])
                self.assertEqual(fixture.read_bytes()[:2],b'MZ')
            finally: scanner.signatures.close()

    def test_thresholds_and_private_helpers_do_not_alert_alone(self):
        rules,_,_=compile_rules(ROOT/'rules')
        self.assertEqual(rules.match(data=b'MZRedLine | Log In',timeout=5),[])
        self.assertEqual(rules.match(data=bytes.fromhex('F9FFD0DE')+b'ordinary harmless text',timeout=5),[])
        self.assertEqual(rules.match(data=b'Ordinary document: STOP|OK ModStart',timeout=5),[])

    def test_missing_managed_file_and_checksum_change_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'rules'
            shutil.copytree(ROOT/'rules',folder)
            path=folder/'eset_redline_panel.yar'
            path.write_bytes(path.read_bytes()+b'\n// changed\n')
            with self.assertRaisesRegex(RuleValidationError,'checksum'): compile_rules(folder)
            path.unlink()
            with self.assertRaisesRegex(RuleValidationError,'missing'): compile_rules(folder)

    def test_includes_compile_warnings_and_duplicate_namespaces_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            rule=root/'localtest.yar'
            rule.write_text('include "outside.yar"')
            with self.assertRaisesRegex(RuleValidationError,'compilation'): compile_rules(root)
            rule.write_text('rule slow { strings: $a = "a" condition: $a }')
            with self.assertRaisesRegex(RuleValidationError,'compilation'): compile_rules(root)
            rule.write_text('rule okay { condition: false }')
            (root/'localtest.yara').write_text('rule other { condition: false }')
            with self.assertRaisesRegex(RuleValidationError,'namespace'): compile_rules(root)

    def test_catalog_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'catalog.json').write_text(json.dumps(dict(schema=1,files=[dict(file='../outside.yar',sha256='a'*64,selected_rules=['outside'])])))
            with self.assertRaisesRegex(RuleValidationError,'catalog filename'): compile_rules(root)

    def test_runtime_failure_retains_known_hash_detection_and_reports_omission(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            fixture=root/'harmless.txt'
            fixture.write_text('Harmless runtime-failure fixture')
            signatures=root/'signatures.json'
            signatures.write_text(json.dumps({hashlib.sha256(fixture.read_bytes()).hexdigest():'Fixture hash'}))
            scanner=Scanner(signatures,root/'rules')
            scanner.rules=Mock()
            scanner.rules.match.side_effect=TimeoutError('Fixture timeout')
            try:
                report=scanner.scan([fixture],lambda:False,lambda *a:None)
                self.assertEqual(report['status'],'Complete with omissions')
                self.assertEqual(len(report['detections']),1)
                self.assertIn('SHA-256: Fixture hash',report['detections'][0]['reasons'])
                self.assertIn('YARA inspection failed',report['errors'][0])
            finally: scanner.signatures.close()


if __name__=='__main__': unittest.main()
