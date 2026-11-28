# Purpose: Verify test remediation broker behavior using controlled fixtures.
# Works with: data.contracts, monitoring.app_changes, platform, platform.remediation_broker,
#   platform.service_changes
# Used by: unittest discovery

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from sentinelav.platform import remediation_broker as broker, service_changes
from sentinelav.data.contracts import change_record
from sentinelav.monitoring.app_changes import resource

OWNER = 'S-1-5-21-1-2-3-1001'


class BrokerTests(unittest.TestCase):
    def test_client_verdicts_commands_paths_and_baselines_are_rejected(self):
        for field in ('command', 'path', 'verdict', 'before', 'evidence', 'options'):
            request = dict(schema=1, operation='prepare', change_ids=['a' * 32])
            request[field] = 'client value'
            with self.assertRaises(ValueError):
                broker.validate_request(request)

    def test_identity_cannot_escape_protected_store(self):
        for value in ('../other', 'C:/somewhere', 'a' * 31, 'g' * 32, None):
            with self.assertRaises(ValueError):
                broker.identity(value)

    def test_replay_cannot_substitute_another_owner(self):
        journal = Mock(owner=OWNER)
        journal.get_operation.return_value = dict(owner_sid='S-1-5-21-9-8-7-1001')
        engine = Mock()
        with self.assertRaises(PermissionError):
            broker.process_request(
                dict(schema=1, operation='execute', plan_id='a' * 32), journal, engine
            )
        engine.execute.assert_not_called()

    def test_gui_execution_request_requires_a_protected_confirmation(self):
        journal = Mock(owner=OWNER)
        journal.get_operation.return_value = dict(owner_sid=OWNER)
        engine = Mock()
        request = dict(schema=1, operation='execute', plan_id='a' * 32)
        with self.assertRaises(PermissionError):
            broker.process_request(request, journal, engine)
        with self.assertRaises(PermissionError):
            broker.process_request(request, journal, engine, lambda plan: False)
        engine.execute.assert_not_called()

    def test_cleanup_does_not_enable_process_file_or_personal_registry_response(self):
        for target in (
            dict(kind='process'),
            dict(kind='file'),
            dict(kind='registry', hive='HKCU'),
            dict(kind='setting_file'),
        ):
            journal = Mock(owner=OWNER)
            journal.change.return_value = dict(resource=target)
            engine = Mock()
            with self.assertRaises(ValueError):
                broker.process_request(
                    dict(schema=1, operation='prepare', change_ids=['a' * 32]), journal, engine
                )
            engine.plan.assert_not_called()

    def test_prepare_uses_engine_and_excludes_related_process_actions(self):
        journal = Mock(owner=OWNER)
        journal.change.return_value = dict(resource=dict(kind='registry', hive='HKLM'))
        engine = Mock()
        engine.plan.return_value = dict(id='b' * 32, state='Planned')
        result = broker.process_request(
            dict(schema=1, operation='prepare', change_ids=['a' * 32]), journal, engine
        )
        engine.plan.assert_called_once_with(['a' * 32], with_related=False)
        self.assertEqual(result['owner_sid'], OWNER)
        journal.operation.assert_called_once()

    def test_demo_eicar_and_unmanaged_rules_cannot_authorize_machine_repair(self):
        self.assertFalse(
            broker.production_detection(dict(reasons=['EICAR test file (not malware)']))
        )
        self.assertFalse(broker.production_detection(dict(reasons=['SHA-256: Harmless demo'])))
        self.assertFalse(
            broker.production_detection(
                dict(yara_matches=[dict(demo=True, source_sha256='a' * 64)])
            )
        )
        self.assertFalse(
            broker.production_detection(dict(yara_matches=[dict(demo=False, source_sha256=None)]))
        )
        self.assertTrue(
            broker.production_detection(dict(reasons=['SHA-256: Independently reviewed threat']))
        )
        self.assertTrue(
            broker.production_detection(
                dict(yara_matches=[dict(demo=False, source_sha256='a' * 64)])
            )
        )

    def test_source_cannot_be_a_production_broker(self):
        with patch.object(broker.sys, 'frozen', False, create=True):
            with self.assertRaises(RuntimeError):
                broker.require_deployment()

    def test_untrusted_acl_is_rejected_before_decrypting_a_plan(self):
        with (
            patch.object(broker, 'verify_windows_acl', side_effect=ValueError('User-writable')),
            patch.object(broker, 'dpapi') as decrypt,
        ):
            with self.assertRaises(ValueError):
                broker.read_protected(Path('untrusted.bin'))
            decrypt.assert_not_called()


class ServiceViewTests(unittest.TestCase):
    def fixture(self, folder, owner=OWNER, age=0):
        view = dict(
            schema=1, owner_sid=owner, generated=time.time() - age, rows=[], receipts=[], errors=[]
        )
        (folder / 'app-changes-view.bin').write_bytes(json.dumps(view).encode())

    def read(self, folder, **kwargs):
        with (
            patch(
                'sentinelav.platform.windows_service.service_paths', return_value=(folder, folder)
            ),
            patch('sentinelav.platform.core.windows_identity.current_sid', return_value=OWNER),
            patch.object(service_changes, 'verify_windows_acl'),
            patch.object(service_changes, 'dpapi', side_effect=lambda raw, *args, **kw: raw),
        ):
            return service_changes.load_view(**kwargs)

    def test_cross_account_history_is_denied(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.fixture(folder, owner='S-1-5-21-4-5-6-1001')
            with self.assertRaises(ValueError):
                self.read(folder)

    def test_stale_history_remains_visible_but_cannot_authorize_preparation(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.fixture(folder, age=100)
            self.assertTrue(self.read(folder)['stale'])
            with self.assertRaises(ValueError):
                self.read(folder, fresh=True)

    def test_service_export_is_encrypted_and_explicit_about_truncation(self):
        row = change_record(
            resource('registry', hive='HKLM', key='fixture', name='fixture', view=64),
            None,
            dict(exists=True, value='sensitive value'),
            baseline=True,
        )
        journal = Mock()
        journal.changes.return_value = [row]

        def protect(raw, **kwargs):
            self.assertTrue(kwargs['machine'])
            return bytes(x ^ 0xAA for x in raw)

        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            with patch.object(service_changes, 'dpapi', side_effect=protect):
                service_changes.publish_view(folder, journal, OWNER, [])
            raw = (folder / 'app-changes-view.bin').read_bytes()
            self.assertNotIn(b'sensitive value', raw)
            self.assertEqual(json.loads(bytes(x ^ 0xAA for x in raw))['rows'][0], row)
