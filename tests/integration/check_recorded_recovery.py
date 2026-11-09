# Purpose: Real encrypted journal, scanner workers and exclusive temporary-file recovery.
# Works with: data.change_journal, data.contracts, detection.inspection, monitoring.app_changes, paths
# Used by: unittest discovery

"""Real encrypted journal, scanner workers and exclusive temporary-file recovery.

Touches only files created by this check; no host persistence or service writes.
"""
import tempfile
from pathlib import Path
from sentinelav.data.change_journal import ChangeJournal
from sentinelav.data.contracts import change_record
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.monitoring.app_changes import WindowsInventory,file_state,resource
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.response.remediation import Remediator,WindowsRemediationBackend


def main():
    with tempfile.TemporaryDirectory(prefix='SentinelAV-recovery-check-') as folder:
        base=Path(folder);config=base/'fixture.ini';control=base/'protected-control.txt'
        original=b'[fixture]\nvalue=original\n';control.write_bytes(b'untouched control')
        config.write_bytes(original);before=file_state(config)
        config.write_bytes(b'[fixture]\nvalue=changed\n');after=file_state(config)
        target=resource('setting_file',path=str(config));record=change_record(target,before,after)
        journal=ChangeJournal(base/'journal');scanner=None
        try:
            journal.commit_observation(target,after,record)
            scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',persistent=True)
            def verify_buffer(data):
                result=scanner.scan_buffer(data)
                if not result['complete']:raise ValueError('Fixture scan incomplete')
                return result['detected']
            engine=Remediator(journal,WindowsRemediationBackend(WindowsInventory([str(config)])),
                lambda path:scanner.scan([path],lambda:False,lambda *args:None)['detections'],verify_buffer=verify_buffer)
            plan=engine.plan([record['id']],'restore');receipt=engine.execute(plan['id'],approved=True)
            assert receipt['state']=='Restoration verified',receipt
            assert config.read_bytes()==original
            assert control.read_bytes()==b'untouched control'
            assert journal.get_operation(plan['id'])['kind']=='RemediationReceipt'
            print('PASS: DPAPI journal, real byte scanner, exclusive exact recovery, persisted receipt, untouched control')
        finally:
            if scanner:scanner.close()
            journal.close()


if __name__=='__main__':main()
