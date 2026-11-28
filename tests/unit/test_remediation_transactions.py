# Purpose: Verify test remediation transactions behavior using controlled fixtures.
# Works with: data.change_journal, response.remediation, response.transaction
# Used by: unittest discovery

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from sentinelav.response.transaction import exclusive_file, RemediationBusy
from sentinelav.data.change_journal import ChangeJournal
from sentinelav.response.remediation import Remediator


def protect(raw, decrypt=False):
    return bytes(b ^ 0xAB for b in raw)


class TransactionTests(unittest.TestCase):
    def test_process_crash_releases_lock_and_competitor_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'execution.lock'
            code = "import os,sys;from sentinelav.response.transaction import exclusive_file\nwith exclusive_file(sys.argv[1]):\n print('locked',flush=True)\n sys.stdin.readline()\n os._exit(17)"
            env = dict(os.environ)
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2] / 'src')
            child = subprocess.Popen(
                [sys.executable, '-c', code, str(path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), 'locked')
                with self.assertRaises(RemediationBusy):
                    with exclusive_file(path):
                        self.fail('Concurrent owner admitted')
                child.communicate('\n', timeout=10)
                self.assertEqual(child.returncode, 17)
                with exclusive_file(path):
                    pass
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)

    def test_lock_released_after_exception(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'execution.lock'
            with self.assertRaises(ValueError):
                with exclusive_file(path):
                    raise ValueError('interrupted')
            with exclusive_file(path):
                pass

    def test_recovery_cannot_reclassify_a_live_operation(self):
        with tempfile.TemporaryDirectory() as name:
            journal = ChangeJournal(Path(name), protect=protect)
            try:
                engine = Remediator(journal, None, None)
                with journal.exclusive():
                    with self.assertRaises(RemediationBusy):
                        engine.reconcile()
            finally:
                journal.close()

    def test_every_interrupted_action_gets_a_receipt_and_none_are_replayed(self):
        with tempfile.TemporaryDirectory() as name:
            journal = ChangeJournal(Path(name), protect=protect)

            class Backend:
                calls = 0

                def read(self, target):
                    return dict(exists=False)

                def apply(self, *args, **kwargs):
                    self.calls += 1
                    raise AssertionError('Must never replay')

            backend = Backend()
            engine = Remediator(journal, backend, lambda path: [])
            actions = [
                dict(
                    change_id=str(i),
                    resource=dict(kind='registry', id=str(i)),
                    action='disable',
                    desired=None,
                )
                for i in range(3)
            ]
            plan = dict(
                id='fixture',
                state='Executing',
                actions=actions,
                results=[
                    dict(change_id='0', resource=actions[0]['resource'], state='Applying'),
                    dict(change_id='1', resource=actions[1]['resource'], state='Pending'),
                ],
            )
            try:
                journal.operation(plan)
                receipt = engine.reconcile()[0]
                self.assertEqual(
                    [r['state'] for r in receipt['results']], ['Verified', 'Skipped', 'Skipped']
                )
                self.assertEqual(backend.calls, 0)
                self.assertFalse(receipt['verification']['complete'])
                self.assertEqual(engine.reconcile(), [])
            finally:
                journal.close()

    def test_recovery_is_not_limited_to_the_visible_history_page(self):
        with tempfile.TemporaryDirectory() as name:
            journal = ChangeJournal(Path(name), protect=protect)
            try:
                journal.operation(dict(id='old', state='Executing', actions=[], results=[]))
                for index in range(501):
                    journal.operation(dict(id=str(index), state='Planned'))
                self.assertFalse(any(row['id'] == 'old' for row in journal.operations()))
                result = Remediator(journal, None, None).reconcile()
                self.assertEqual([row['id'] for row in result], ['old'])
                self.assertFalse(result[0]['verification']['complete'])
            finally:
                journal.close()
