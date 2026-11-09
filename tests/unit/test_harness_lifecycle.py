# Purpose: Verify test harness lifecycle behavior using controlled fixtures.
# Works with: lab.qualification.backends, lab.qualification.catalog, lab.qualification.contracts,
#   lab.qualification.guest_inventory, lab.qualification.guest_process
# Used by: unittest discovery

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from sentinelav.lab.qualification.contracts import CaseDefinition,Observation,CaseResult,SuiteManifest,digest,validate_samples
from sentinelav.lab.qualification.scoring import score_case,qualify,detection_metrics,upper_bound
from sentinelav.lab.qualification.store import RunStore,exclusive
from sentinelav.lab.qualification.reporting import render,redact,escape
from sentinelav.lab.qualification.backends import read_export,reconcile,Sandbox,HyperV
from sentinelav.lab.qualification.catalog import suite
from tests.unit.harness_fixtures import HarnessFixture

class HarnessLifecycleTests(HarnessFixture,unittest.TestCase):
    def test_fixture_resource_scope(self):
        from sentinelav.lab.qualification.guest_inventory import resources
        for artifact in (dict(kind='registry',key='SYSTEM',name='bad'),dict(kind='service',name='WinDefend'),dict(kind='task',name='Microsoft'),dict(kind='file',relative='../Windows/x')):
            with self.assertRaises(ValueError):resources(dict(expected_artifacts=[artifact]),Path('C:/SentinelAV-Test'))

    def test_failed_hyperv_initialization_never_calls_start(self):
        from sentinelav.lab.qualification.backends import Blocked
        with tempfile.TemporaryDirectory() as d,patch('sentinelav.lab.qualification.backend_hyperv.powershell') as command:
            with self.assertRaises(Blocked):HyperV(d,d,d,lambda:False,lambda _:None)
            command.assert_not_called()

    def test_unavailable_selected_pe_remains_in_raw_denominator(self):
        rows=[]
        for i in range(200):
            row=self.sample();row.update(sha256=f'{i:064x}',qualification=True,independently_selected=True,
                declared_format='PE',format='PE' if i<150 else 'Unavailable',available=i<150,
                confirmed=i<150,evidence_linked=i<150,coverage_complete=i<150,family=f'family-{i%20}',family_verified=True)
            rows.append(row)
        o=self.observation(samples=rows);r=asdict(score_case(self.case,o,self.versions))
        summary=qualify(self.manifest,[r]);gate=summary['gates']['raw_detection']
        self.assertEqual(gate['status'],'failed');self.assertEqual(gate['metrics']['selected_malware'],200)
        self.assertEqual(gate['metrics']['recall_all_selected'],.75)

    def test_low_system_space_blocks_sandbox_not_f_work(self):
        from types import SimpleNamespace
        from sentinelav.lab.qualification.runner import preflight,sandbox_storage_problem
        with tempfile.TemporaryDirectory() as d:
            project=Path(d);python=project/'.venv/Scripts/python.exe';python.parent.mkdir(parents=True);python.touch()
            with patch('sentinelav.lab.qualification.runner.shutil.disk_usage',return_value=SimpleNamespace(free=3*1024**3)),patch('sentinelav.lab.qualification.runner.Workspace.check'):
                self.assertEqual(preflight(project,project),[])
                self.assertIn('Windows Sandbox',sandbox_storage_problem())

    def test_work_temp_sets_python_and_subprocess_paths(self):
        import os
        from sentinelav.lab.qualification.runner import configure_work_temporary
        previous=tempfile.tempdir
        try:
            with tempfile.TemporaryDirectory() as d,patch.dict(os.environ),patch('sentinelav.lab.qualification.runner.Workspace.area',return_value=Path(d)):
                target=configure_work_temporary(Path(d))
                self.assertEqual(Path(tempfile.gettempdir()),target)
                self.assertEqual(os.environ['TEMP'],str(target));self.assertEqual(os.environ['TMP'],str(target))
        finally:tempfile.tempdir=previous

    def test_connection_is_limited_to_owned_existing_guest(self):
        from sentinelav.lab.qualification.backends import Blocked
        owned='11111111-1111-1111-1111-111111111111'
        with tempfile.TemporaryDirectory() as d:
            backend=Sandbox(d,d,d,lambda:False,lambda _:None);backend.owner=dict(backend='sandbox',guest_id=owned)
            with patch.object(backend,'listed',return_value=[dict(Id='22222222-2222-2222-2222-222222222222')]),patch('sentinelav.lab.qualification.backend_sandbox.run') as command:
                with self.assertRaises(Blocked):backend.connect()
                command.assert_not_called()
            with patch.object(backend,'listed',return_value=[dict(Id=owned)]),patch('sentinelav.lab.qualification.backend_sandbox.run',return_value='') as command:
                backend.connect();self.assertEqual(command.call_args.args[0],['wsb.exe','connect','--id',owned,'--raw'])

    def test_setup_metadata_roundtrip_and_scope(self):
        import re
        raw=b'{"schema":1,"succeeded":true}'
        with tempfile.TemporaryDirectory() as d:
            backend=Sandbox(d,d,d,lambda:False,lambda _:None)
            def execute(code):
                if '1073741824+$b.Length' in code:return 1073741824+len(raw)
                offset=int(re.search(r'if\(\((\d+)\+\$i\)',code)[1])
                return 1073741824+int.from_bytes(raw[offset:offset+3].ljust(3,b'\0'),'little')
            with patch.object(backend,'exec',side_effect=execute) as command:
                self.assertTrue(backend.read_metadata('C:/SentinelAV-Test/TelemetrySetup/result.json',compressed=False)['succeeded'])
                command.reset_mock()
                with self.assertRaises(ValueError):backend.read_metadata('C:/Users/Private/result.json',compressed=False)
                command.assert_not_called()

    def test_setup_requires_explicit_success_receipt(self):
        from sentinelav.lab.qualification.backends import Blocked
        with tempfile.TemporaryDirectory() as d:
            backend=Sandbox(d,d,d,lambda:False,lambda _:None)
            with patch.object(backend,'exec',return_value=0),patch.object(backend,'read_metadata',return_value=dict(succeeded=False,stage='install-sysmon',error='fixture failure')):
                with self.assertRaisesRegex(Blocked,'fixture failure'):backend.setup_telemetry()
            self.assertFalse(json.loads((Path(d)/'telemetry-setup.json').read_text())['succeeded'])

    def test_missing_guest_export_preserves_exit_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as d:
            backend=Sandbox(d,d,d,lambda:False,lambda _:None)
            def execute(code,*args):
                if 'Start-Process' in code:return 73
                if 'if(Test-Path' in code:return 77
                return 0
            with patch.object(backend,'exec',side_effect=execute),patch.object(backend,'read_metadata') as read:
                with self.assertRaisesRegex(RuntimeError,'exited 73 without a bounded diagnostic export'):
                    backend.execute(dict(nonce='missingexport',case=dict(id='fixture',seconds=1)))
                read.assert_not_called()
            self.assertEqual(json.loads((Path(d)/'execution-missingexport.json').read_text())['exit_code'],73)

    def test_guest_engine_launcher_refuses_host_before_process_creation(self):
        from sentinelav.lab.qualification.guest_process import launch_engine
        with patch('sentinelav.lab.qualification.guest_context.guard',return_value=False),patch('sentinelav.lab.qualification.guest_process.subprocess.Popen') as process:
            with self.assertRaisesRegex(ValueError,'verified offline guest'):launch_engine(Path('C:/outside/engine'),dict(backend='sandbox'))
            process.assert_not_called()

    def test_guest_engine_launcher_refuses_out_of_scope_data(self):
        from sentinelav.lab.qualification.guest_process import launch_engine
        with patch('sentinelav.lab.qualification.guest_context.guard',return_value=True),patch('sentinelav.lab.qualification.guest_process.subprocess.Popen') as process:
            with self.assertRaisesRegex(ValueError,'owned qualification case'):launch_engine(Path('C:/Windows/engine'),dict(backend='sandbox'))
            process.assert_not_called()
