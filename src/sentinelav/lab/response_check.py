# Purpose: Harmless Qt response integration check, invoked only by --self-test.
# Works with: sibling modules in lab
# Used by: entrypoint

"""Harmless Qt response integration check, invoked only by --self-test.

Only dialogs are supplied fixture answers. Scanning, button signals, workers,
encryption, file operations and audit storage use the normal application code.
"""
import hashlib
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QFileDialog, QPushButton, QTabWidget


def require(condition, message):
    """Raise a self-test failure with the message if the condition is false."""
    if not condition:
        raise RuntimeError('Response self-test: '+message)


def wait_for(app, predicate, seconds=30):
    """Keep the Qt event loop running until predicate() is true, failing after `seconds`."""
    deadline=time.monotonic()+seconds
    while not predicate():
        require(time.monotonic()<deadline,'worker timed out')
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents,50)
        time.sleep(.01)
    app.processEvents()


def check_response_ui(app, window, evidence_dir):
    """Self-test the quarantine and restore workflow through the real window controls.

    A harmless marker file is scanned, quarantined (checking the encrypted copy contains no
    plaintext), restore onto an existing file is refused, then the file is restored and detected
    again. Only the dialog answers are faked. Returns a PASS record with evidence.
    """
    confirmations=[]
    def confirm(title,text):
        """Fake confirmation dialog that records its title and always answers Yes."""
        confirmations.append(title)
        return True

    # Source/installation paths are protected by response guards. Fixtures are
    # reserved under the user's temporary directory, never an existing file.
    with tempfile.TemporaryDirectory(prefix='SentinelAV-response-') as temp:
        fixture=Path(temp)/'harmless-marker.txt'
        content=b'SENTINELAV_DEMO_THREAT_7C23A'
        fixture.write_bytes(content)
        expected=hashlib.sha256(content).hexdigest()
        with patch.object(QFileDialog,'getOpenFileNames',return_value=([str(fixture)],'')):
            window.select_files_button.click()
        wait_for(app,lambda:window.worker is None)
        rows=[i for i,d in enumerate(window.pending_detections) if Path(d['path'])==fixture]
        require(len(rows)==1,'expected one matching detected fixture')
        require(window.pending_detections[rows[0]]['sha256']==expected,'detection digest differs')
        window.buttons[3].click()
        window.pending_table.selectRow(rows[0])
        with patch.object(window,'confirm',side_effect=confirm):
            window.quarantine_button.click()
            wait_for(app,lambda:window.response_worker is None)
            require(not fixture.exists(),window.response_status.text())
            record=window.quarantine_records[0]
            require(record['state']=='Quarantined','UI state is not Quarantined')
            blob=window.store.path.parent/'quarantine'/(record['id']+'.sav')
            require(blob.is_file() and content not in blob.read_bytes(),'encrypted blob missing or plaintext')
            window.stack.widget(3).findChild(QTabWidget).setCurrentIndex(1)
            window.quarantine_table.selectRow(0)
            app.processEvents()
            require(window.grab().save(str(evidence_dir/'response-quarantined.png')),'quarantine screenshot failed')
            buttons=[b for b in window.stack.widget(3).findChildren(QPushButton) if b.text()=='Restore…']
            require(len(buttons)==1,'restore control is ambiguous')
            # First prove that the UI preserves existing destination contents.
            occupied=Path(temp)/'existing.txt'
            occupied.write_bytes(b'Preserve this ordinary fixture')
            with patch.object(QFileDialog,'getSaveFileName',return_value=(str(occupied),'')):
                buttons[0].click()
                wait_for(app,lambda:window.response_worker is None)
            require(occupied.read_bytes()==b'Preserve this ordinary fixture','existing destination changed')
            require(window.response_status.text().startswith('Action failed:') and blob.exists(),'overwrite refusal not visible')
            require(window.quarantine_records[0]['state']=='Quarantined','failed restore changed quarantine state')
            window.quarantine_table.selectRow(0)
            with patch.object(QFileDialog,'getSaveFileName',return_value=(str(fixture),'')):
                buttons[0].click()
                wait_for(app,lambda:window.response_worker is None)
        require(fixture.read_bytes()==content,'restored bytes differ')
        restored_hash=hashlib.sha256(fixture.read_bytes()).hexdigest()
        require(restored_hash==expected and not blob.exists(),'restore digest/blob state differs')
        require(window.quarantine_records[0]['state']=='Restored','UI state is not Restored')
        require(not window.store.get('trusted_hashes',[]),'ordinary restore added trust')
        kinds={e['kind'] for e in window.store.events()}
        require({'File quarantined','File restored','Response failed'}.issubset(kinds),'audit events missing')
        require(window.grab().save(str(evidence_dir/'response-restored.png')),'restore screenshot failed')
        window.start_scan([fixture],'Restored harmless fixture')
        wait_for(app,lambda:window.worker is None)
        require(len(window.store.history()[0]['detections'])==1,'restored content no longer detected')
        result=dict(status='PASS',mode='automated Qt controls; fixture dialog answers',
                    original_sha256=expected,restored_sha256=restored_hash,
                    original_removed=True,encrypted_blob_verified=True,
                    overwrite_refused=True,restored_state_verified=True,
                    restored_content_detected_again=True,trust_unchanged=True,
                    audit_verified=True,confirmations=confirmations)
    require(not Path(temp).exists(),'temporary fixture cleanup failed')
    window.refresh()
    result['fixture_cleanup']=True
    return result
