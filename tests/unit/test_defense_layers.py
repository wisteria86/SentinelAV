# Purpose: Verify test defense layers behavior using controlled fixtures.
# Works with: detection.archive_inspection, detection.engine, detection.inspection, detection.memory_inspection,
#   detection.preexecution
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import queue
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile,ZIP_DEFLATED
from sentinelav.detection.archive_inspection import inspect_zip
from sentinelav.detection.engine import Scanner
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.monitoring.process_telemetry import ProcessGraph
from sentinelav.response.auto_response import eligibility
from sentinelav.detection.preexecution import verdict
from sentinelav.platform.integrity import verify_installation,file_hash
from sentinelav.detection.yara_rules import compile_rules

ROOT=RESOURCE_ROOT


class DefenseLayerTests(unittest.TestCase):
    def zip_bytes(self,entries):
        buffer=io.BytesIO()
        with ZipFile(buffer,'w',ZIP_DEFLATED) as archive:
            for name,value in entries: archive.writestr(name,value)
        return buffer.getvalue()

    def test_zip_member_detection_keeps_outer_identity_and_never_extracts(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'signatures.json').write_text('{}')
            target=root/'archive.zip'
            target.write_bytes(self.zip_bytes([('ordinary.txt',b'SENTINELAV_DEMO_THREAT_7C23A')]))
            scanner=Scanner(root/'signatures.json',ROOT/'rules')
            try:
                report=scanner.scan([target],lambda:False,lambda *a:None)
                finding=next(d for d in report['detections'] if d.get('member_chain'))
                self.assertEqual(finding['sha256'],hashlib.sha256(target.read_bytes()).hexdigest())
                self.assertEqual(finding['member_chain'],['ordinary.txt'])
                self.assertFalse((root/'ordinary.txt').exists())
            finally: scanner.signatures.close()

    def test_archive_traversal_depth_and_ratio_are_visible_omissions(self):
        analyze=lambda data:([],[],[])
        raw=self.zip_bytes([('../escape.txt',b'ordinary'),('huge.txt',b'A'*100000)])
        findings,omissions,_=inspect_zip(raw,analyze)
        self.assertFalse(findings)
        self.assertTrue(any('Unsafe' in error for error in omissions))
        self.assertTrue(any('ratio' in error for error in omissions))
        nested=self.zip_bytes([('inner.zip',self.zip_bytes([('nested.zip',self.zip_bytes([('a.txt',b'a')]))]))])
        _,errors,_=inspect_zip(nested,analyze)
        self.assertTrue(any('depth' in error for error in errors))

    def test_prepended_zip_is_inspected_without_loading_executable_content(self):
        raw=b'Inert prefix, not executable\0'+self.zip_bytes([('a.txt',b'marker')])
        analyze=lambda data:(['Fixture marker'] if data==b'marker' else [],[],[])
        findings,errors,_=inspect_zip(raw,analyze)
        self.assertEqual(len(findings),1)
        self.assertEqual(errors,[])

    def test_ancestry_rejects_reused_parent_pid(self):
        graph=ProcessGraph()
        graph.observe(dict(pid=10,ppid=1,create_time=1,name='winword.exe'))
        graph.observe(dict(pid=11,ppid=10,create_time=2,name='cmd.exe'))
        child=dict(pid=12,ppid=11,create_time=3,name='powershell.exe')
        self.assertEqual([a['name'] for a in graph.ancestors(child)],['cmd.exe','winword.exe'])
        graph.observe(dict(pid=10,ppid=1,create_time=9,name='unrelated.exe'))
        self.assertEqual([a['name'] for a in graph.ancestors(child)],['cmd.exe'])

    def test_response_requires_opt_in_scope_and_independent_approved_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            target=root/'a.txt'; target.write_text('ordinary')
            event=dict(path=str(target),sha256='a'*64,reasons=['SHA-256: Fixture'])
            policy=dict(enabled=True,approved_hashes=['a'*64],roots=[str(root)])
            self.assertTrue(eligibility(event,policy)[0])
            self.assertFalse(eligibility(event,{})[0])
            self.assertFalse(eligibility(dict(event,reasons=['YARA: Fixture']),policy)[0])
            self.assertFalse(eligibility(dict(event,member_chain=['a.txt']),policy)[0])
            self.assertFalse(eligibility(dict(event,path=str(root/'..'/'outside.txt')),policy)[0])

    def test_preexecution_never_treats_no_match_as_safety(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); target=root/'a.txt'; target.write_text('ordinary')
            (root/'signatures.json').write_text('{}')
            scanner=Scanner(root/'signatures.json',root/'rules')
            try: report=scanner.scan([target],lambda:False,lambda *a:None)
            finally: scanner.signatures.close()
            self.assertEqual(verdict(target,report)['decision'],'Not approved')
            target.write_text('Changed')
            self.assertEqual(verdict(target,report)['decision'],'Indeterminate')
            self.assertFalse(verdict(target,report)['system_wide_enforcement'])

    def test_integrity_checks_fail_on_changed_file_and_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); code=root/'code.bin'; code.write_bytes(b'harmless')
            manifest=root/'code-integrity.json'
            manifest.write_text(json.dumps({'code.bin':file_hash(code)}))
            self.assertEqual(verify_installation(root)['files'],1)
            code.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'mismatch'): verify_installation(root)
            manifest.write_text(json.dumps({'../outside.bin':'a'*64}))
            with self.assertRaisesRegex(ValueError,'path'): verify_installation(root)

    def test_memory_candidates_are_separate_from_file_rules(self):
        rules,summary,_=compile_rules(ROOT/'rules/memory')
        self.assertEqual(summary['research_rules'],2)
        strings=['RedLine | Log In','RedLine | Autofilles Viewer','RedLine | Choose Browser',
                 'RedLine | Cookie Viewer','RedLine | Credit Card Viewer','RedLine | Files Viewer']
        self.assertTrue(rules.match(data='\0'.join(strings).encode(),timeout=1))
        ordinary,_,_=compile_rules(ROOT/'rules')
        self.assertFalse(ordinary.match(data='\0'.join(strings).encode(),timeout=1))

    def test_amsi_consumer_is_not_a_provider_and_limits_input(self):
        from sentinelav.platform.amsi_client import scan_buffer
        with self.assertRaises(ValueError): scan_buffer(b'X'*(4*1024*1024+1))


class IsolatedWorkerTests(unittest.TestCase):
    def test_worker_failure_retains_already_streamed_hash_finding(self):
        scanner=IsolatedScanner.__new__(IsolatedScanner)
        scanner.job=None
        scanner.messages=queue.Queue()
        finding=dict(path='C:/owned/fixture.txt',sha256='a'*64,reasons=['SHA-256: Fixture'],yara_matches=[])
        scanner.messages.put(dict(protocol=1,type='finding',finding=finding))
        states=iter([None,0])
        scanner.process=SimpleNamespace(poll=lambda:next(states,0),stdin=SimpleNamespace(write=lambda data:len(data),flush=lambda:None))
        scanner.transport_errors=['Simulated parser exit']
        try:
            result=scanner.exchange(dict(command='scan',roots=['C:/owned/fixture.txt']),lambda:False,lambda *a:None,1)
            self.assertEqual(result['status'],'Complete with omissions')
            self.assertEqual(result['detections'],[finding])
        finally: scanner.process=None

    def test_real_worker_detects_fixture_and_cancellation_releases_job(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fixture.txt'; target.write_text('SENTINELAV_DEMO_THREAT_7C23A')
            scanner=IsolatedScanner(ROOT/'signatures.json',ROOT/'rules')
            process=scanner.process
            result=scanner.scan([target],lambda:False,lambda *a:None)
            self.assertTrue(result['detections'])
            self.assertIsNone(scanner.process)
            self.assertIsNotNone(process.poll())
            scanner=IsolatedScanner(ROOT/'signatures.json',ROOT/'rules')
            process=scanner.process
            result=scanner.scan([target],lambda:True,lambda *a:None)
            self.assertEqual(result['status'],'Cancelled')
            self.assertIsNotNone(process.poll())

    def test_memory_rejects_system_pid_before_reading(self):
        from sentinelav.detection.memory_inspection import inspect_memory
        with self.assertRaises(ValueError): inspect_memory(4,1,lambda data:([],[],[]))

    def test_persistent_worker_recovers_after_exit_and_closed_timeout_state(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'inert-marker.txt'
            target.write_text('SENTINELAV_DEMO_THREAT_7C23A')
            scanner=IsolatedScanner(ROOT/'signatures.json',ROOT/'rules',persistent=True)
            try:
                for failure in ('exit','closed'):
                    with self.subTest(failure=failure):
                        previous=scanner.process
                        if failure=='exit':
                            previous.kill()
                            previous.wait(timeout=5)
                        else: scanner.close()
                        result=scanner.scan([target],lambda:False,lambda *args:None)
                        self.assertEqual(result['status'],'Complete')
                        self.assertTrue(result['detections'])
                        self.assertTrue(result['worker_restarted'])
                        self.assertIsNot(scanner.process,previous)
            finally: scanner.close()


if __name__=='__main__': unittest.main()
