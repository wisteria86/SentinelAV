# Purpose: Verify test app changes behavior using controlled fixtures.
# Works with: data.change_journal, data.contracts, monitoring.app_changes, response.change_reports,
#   response.remediation
# Used by: unittest discovery

import json
from pathlib import Path
import tempfile
import unittest
from sentinelav.data.change_journal import ChangeJournal
from sentinelav.data.contracts import change_record,fingerprint
from sentinelav.monitoring.app_changes import ChangeTracker,resource
from sentinelav.response.remediation import Remediator
from sentinelav.workspace import Workspace


def protect(raw,decrypt=False):
    # Test-only reversible encryption substitutes for account-bound DPAPI.
    return bytes(x^0xA7 for x in raw)


class Inventory:
    settings=[]
    def __init__(self,rows,complete=('registry',)):self.rows,self.complete=rows,list(complete)
    def collect(self):return dict(rows=self.rows,errors=[],complete=self.complete)


class Backend:
    def __init__(self,state):self.state=state;self.calls=[]
    def read(self,target):return self.state
    def apply(self,target,action,state,expected=None):self.calls.append(action);self.state=dict(exists=False) if action=='disable' else state


class AppChangesTests(unittest.TestCase):
    def test_disabled_task_trigger_is_not_disabled_task(self):
        from sentinelav.response.remediation import task_disabled
        self.assertFalse(task_disabled(dict(xml='<Task><Triggers><TimeTrigger><Enabled>false</Enabled></TimeTrigger></Triggers><Settings><Enabled>true</Enabled></Settings></Task>')))
        self.assertTrue(task_disabled(dict(xml='<Task><Settings><Enabled>false</Enabled></Settings></Task>')))

    def test_reconciliation_finds_new_persistence_reference(self):
        from unittest.mock import patch
        from sentinelav.response.remediation import WindowsRemediationBackend
        target=resource('registry',hive='HKCU',key='fixture',name='New',view=64)
        inventory=Inventory([(target,dict(exists=True,value='fixture'))],complete=('registry','startup_file','task','service','setting_file'))
        backend=WindowsRemediationBackend(inventory)
        with patch('sentinelav.response.remediation_backend.referenced_paths',return_value=['incident-file']):
            result=backend.verify_incident(dict(actions=[dict(evidence=[dict(path='incident-file')])]))
        self.assertFalse(result['complete']);self.assertEqual(len(result['remnants']),1)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.journal=ChangeJournal(self.folder,protect=protect)
        self.addCleanup(self.journal.close)
        self.target=resource('registry',hive='HKCU',key=r'Software\Microsoft\Windows\CurrentVersion\Run',name='Example',view=64)
        self.state=dict(exists=True,value='"C:\\fixture.exe"',type=1)

    def test_preexisting_and_new_addition_are_distinct(self):
        inventory=Inventory([(self.target,self.state)])
        tracker=ChangeTracker(self.journal,inventory);first=tracker.poll()['changes'][0]
        self.assertTrue(first['preexisting']);self.assertFalse(first['baseline_available'])
        self.assertEqual(tracker.poll()['changes'],[])
        other=resource('registry',hive='HKCU',key=self.target['key'],name='New',view=64)
        inventory.rows.append((other,self.state));added=tracker.poll()['changes'][0]
        self.assertFalse(added['preexisting']);self.assertEqual(added['before'],dict(exists=False))

    def test_incomplete_inventory_does_not_invent_deletion(self):
        inventory=Inventory([(self.target,self.state)]);tracker=ChangeTracker(self.journal,inventory);tracker.poll()
        inventory.rows=[];inventory.complete=[]
        self.assertEqual(tracker.poll()['changes'],[])
        inventory.complete=['registry'];self.assertEqual(tracker.poll()['changes'][0]['after'],dict(exists=False))

    def test_sensitive_state_is_not_stored_in_plaintext(self):
        row=change_record(self.target,None,self.state,baseline=True)
        self.journal.commit_observation(self.target,self.state,row)
        blob=self.journal.db.execute('SELECT payload FROM changes').fetchone()[0]
        self.assertNotIn(b'fixture.exe',blob)
        self.assertEqual(self.journal.change(row['id']),row)

    def test_export_omits_sensitive_payloads_and_error_strings(self):
        from sentinelav.response.change_reports import summary
        row=change_record(self.target,None,dict(exists=True,value='--password=secret-value'),baseline=True)
        receipt=dict(id='receipt',kind='RemediationReceipt',state='Unresolved',mode='cleanup',
            results=[dict(change_id=row['id'],state='Unresolved',resource=self.target,reason='secret-value')])
        report=json.dumps(summary([row],[receipt]))
        self.assertNotIn('secret-value',report);self.assertNotIn('password',report)

    def test_verified_attribution_requires_process_identity(self):
        with self.assertRaises(ValueError):change_record(self.target,None,self.state,attribution='Verified')

    def make_engine(self):
        row=change_record(self.target,dict(exists=False),self.state)
        self.journal.commit_observation(self.target,self.state,row)
        backend=Backend(self.state)
        # Replace path extraction only to keep the fixture platform independent.
        engine=Remediator(self.journal,backend,lambda path:[dict(path=path,sha256='a'*64)])
        return row,backend,engine

    def test_conflict_after_approval_causes_no_action(self):
        from unittest.mock import patch
        row,backend,engine=self.make_engine()
        with patch('sentinelav.response.remediation.referenced_paths',return_value=['fixture']):
            plan=engine.plan([row['id']],with_related=False);backend.state=dict(exists=True,value='legitimate later update',type=1)
            result=engine.execute(plan['id'],approved=True)
        self.assertEqual(backend.calls,[]);self.assertEqual(result['results'][0]['state'],'Unresolved')

    def test_fresh_evidence_required_and_success_verified(self):
        from unittest.mock import patch
        row,backend,engine=self.make_engine()
        with patch('sentinelav.response.remediation.referenced_paths',return_value=['fixture']):
            plan=engine.plan([row['id']],with_related=False)
            self.assertTrue(any(node['id']=='a'*64 for node in plan['incident_graph']['nodes']))
            result=engine.execute(plan['id'],approved=True)
        self.assertEqual(backend.calls,['disable']);self.assertEqual(result['results'][0]['state'],'Verified')
        self.assertEqual(self.journal.get_operation(plan['id'])['kind'],'RemediationReceipt')

    def test_disabling_persistence_cannot_claim_payload_removal(self):
        from unittest.mock import patch
        row,backend,engine=self.make_engine()
        read=backend.read
        backend.read=lambda target:dict(exists=True,sha256='a'*64) if target['kind']=='file' else read(target)
        backend.verify_incident=lambda plan:dict(complete=True,remnants=[],omissions=[])
        with patch('sentinelav.response.remediation.referenced_paths',return_value=['fixture']):
            plan=engine.plan([row['id']],with_related=False);result=engine.execute(plan['id'],approved=True)
        self.assertFalse(result['verification']['complete'])
        self.assertEqual(result['verification']['remnants'][0]['reason'],'Detected incident payload remains')
        self.assertTrue(result['state'].startswith('Partially'))

    def test_directory_argument_does_not_authorize_unrelated_child(self):
        from unittest.mock import patch
        row,backend,engine=self.make_engine()
        engine.verify=lambda path:[dict(path=str(Path(path)/'unrelated.exe'),sha256='a'*64)]
        with patch('sentinelav.response.remediation.referenced_paths',return_value=['directory']):
            with self.assertRaises(ValueError):engine.plan([row['id']],with_related=False)
        self.assertEqual(backend.calls,[])

    def test_preexisting_entry_cannot_restore_unknown_state(self):
        row=change_record(self.target,None,self.state,baseline=True)
        self.journal.commit_observation(self.target,self.state,row)
        engine=Remediator(self.journal,Backend(self.state),lambda p:[])
        with self.assertRaises(ValueError):engine.plan([row['id']],'restore')

    def test_recovery_snapshot_is_rechecked_after_approval(self):
        import base64,hashlib
        target=resource('setting_file',path=str(self.folder/'settings.ini'))
        raw=b'ordinary=true'
        before=dict(exists=True,content=base64.b64encode(raw).decode(),sha256=hashlib.sha256(raw).hexdigest())
        after=dict(exists=True,sha256='a'*64)
        row=change_record(target,before,after)
        self.journal.commit_observation(target,after,row)
        backend=Backend(after);detected=[False]
        engine=Remediator(self.journal,backend,lambda p:[],verify_buffer=lambda data:detected[0])
        plan=engine.plan([row['id']],'restore');detected[0]=True
        receipt=engine.execute(plan['id'],approved=True)
        self.assertEqual(backend.calls,[])
        self.assertEqual(receipt['results'][0]['state'],'Unresolved')

    def test_workspace_immutable_reports_and_quota(self):
        work=Workspace(self.folder/'work',quota=1024,reserve=0)
        one=work.immutable_report(dict(result='one'));two=work.immutable_report(dict(result='two'))
        self.assertNotEqual(one,two);self.assertEqual(json.loads(one.read_text())['result'],'one')
        with self.assertRaises(OSError):work.check(1024)

    def test_cache_retention_preserves_source_datasets_and_evidence(self):
        import os,time
        work=Workspace(self.folder/'work',reserve=0)
        paths=[]
        for name in ('cache/pip/old','cache/speakeasy/source','evaluations/receipt','datasets/features'):
            path=work.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('preserve')
            os.utime(path,(time.time()-90*86400,)*2);paths.append(path)
        result=work.prune_cache()
        self.assertEqual(result['files'],1);self.assertFalse(paths[0].exists())
        self.assertTrue(all(path.exists() for path in paths[1:]))
