# Purpose: Exercise real removal and real-time paths on detected samples inside the offline guest.
# Works with: lab.qualification.zoo_guest, response.response, monitoring.monitoring, data.storage

"""Exercise real removal and real-time paths on detected samples inside the offline guest.

Samples are only written and read, never launched. Failures become recorded results,
so a broken response path shows up in the report instead of aborting the batch.
"""
import hashlib
import threading
import time
import uuid

from sentinelav.data.storage import Store
from sentinelav.monitoring.monitoring import Monitor
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.response.auto_response import policy_for
from sentinelav.response.response import ResponseService


def _workspace(root, label):
    folder = root / (label + '-' + uuid.uuid4().hex[:12])
    (folder / 'files').mkdir(parents=True)
    (folder / 'state').mkdir()
    return folder


def response_cycle(raw, suffix, root, settings):
    """Quarantine, prove the original is gone and encrypted, restore, re-quarantine, delete."""
    result = dict(completed=False)
    started = time.monotonic()
    store = None
    try:
        folder = _workspace(root, 'response')
        target = folder / 'files' / ('sample' + suffix)
        target.write_bytes(raw)
        store = Store(folder / 'state' / 'sentinelav.db')
        store.set('inspection_options', dict(settings))
        service = ResponseService(store, RESOURCE_ROOT)
        identity = hashlib.sha256(raw).hexdigest()
        detection = dict(path=str(target), sha256=identity, reasons=['Evaluation response cycle'])
        record = service.quarantine_file(detection)
        result['original_removed'] = not target.exists()
        blob = service.vault / (record['id'] + '.sav')
        sealed = blob.read_bytes()
        slice_start = max(0, len(raw) // 2 - 32)
        result['encrypted_at_rest'] = raw[slice_start:slice_start + 64] not in sealed and raw[:64] not in sealed
        restored = folder / 'files' / ('restored' + suffix)
        service.restore(record['id'], str(restored))
        result['restored_identical'] = hashlib.sha256(restored.read_bytes()).hexdigest() == identity
        second = service.quarantine_file(dict(detection, path=str(restored)))
        removed = service.delete(second['id'])
        result['deleted'] = removed['state'] == 'Deleted' and not (service.vault / (second['id'] + '.sav')).exists() and not restored.exists()
        result['completed'] = all(result.get(key) for key in ('original_removed', 'encrypted_at_rest', 'restored_identical', 'deleted'))
    except Exception as error:
        result['error'] = (type(error).__name__ + ': ' + str(error))[:200]
    finally:
        if store:
            store.db.close()
    result['seconds'] = round(time.monotonic() - started, 2)
    return result


def realtime_check(raw, suffix, root, settings, patience=90):
    """Drop a sample into a watched folder and time detection and any automatic quarantine."""
    result = dict(detected=False)
    monitor = thread = None
    try:
        folder = _workspace(root, 'realtime')
        events = []
        config = dict(folders=[str(folder / 'files')], processes=False, sysmon=False, behavior=False, network=False,
                      signatures=RESOURCE_ROOT / 'signatures.json', rules=RESOURCE_ROOT / 'rules', max_mb=64, exclusions=[str(folder / 'state')],
                      trusted_hashes=[], inspection_options=dict(settings), auto_response=policy_for(None, [folder / 'files']), data_dir=str(folder / 'state'))
        store = Store(folder / 'state' / 'sentinelav.db')
        store.set('inspection_options', dict(settings))
        store.db.close()
        monitor = Monitor(config, events.append, lambda state: None)
        thread = threading.Thread(target=monitor.run, name='zoo-realtime', daemon=True)
        thread.start()
        limit = time.monotonic() + 60
        while time.monotonic() < limit and not any(event['kind'] == 'Monitoring started' for event in events):
            time.sleep(.1)
        target = folder / 'files' / ('dropped' + suffix)
        started = time.monotonic()
        target.write_bytes(raw)
        limit = started + patience
        while time.monotonic() < limit:
            found = [event for event in events if event['kind'] == 'Threat detected']
            if found and not result['detected']:
                result.update(detected=True, seconds_to_detect=round(time.monotonic() - started, 2), automatic_eligible=found[0].get('automatic_response_eligible'))
            if result['detected'] and (not result['automatic_eligible'] or not target.exists()):
                break
            time.sleep(.1)
        result['file_removed'] = not target.exists()
        if result['file_removed'] and result['detected']:
            result['seconds_to_quarantine'] = round(time.monotonic() - started, 2)
    except Exception as error:
        result['error'] = (type(error).__name__ + ': ' + str(error))[:200]
    finally:
        if monitor:
            monitor.stop.set()
        if thread:
            thread.join(30)
    return result
