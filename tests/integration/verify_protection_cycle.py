# Purpose: Prove the real watcher, scan workers, vault and policy work together on harmless files.
# Works with: monitoring.monitoring, response.auto_response, response.response, data.storage
# Used by: the CLI and docs/deliverables/RUNNING.md

"""Prove the real watcher, scan workers, vault and policy work together on harmless files.

Nothing is mocked and nothing is executed. The fixtures are inert text: a project test
marker and scripts that only look risky to the scanner. Run with TEMP on the work drive,
because response actions refuse paths inside the installation.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time

from sentinelav.data.storage import Store
from sentinelav.monitoring.monitoring import Monitor
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.response.auto_response import policy_for
from sentinelav.response.response import ResponseService
from sentinelav.response.vault import read_plain

MARKER=b'SENTINELAV_DEMO_THREAT_7C23A'
WORM=(b'On Error Resume Next\r\nSet f=CreateObject("Scripting.FileSystemObject")\r\nf.CopyFile WScript.ScriptFullName,"C:\\x.vbs"\r\n'
      b'Set o=CreateObject("Outlook.Application")\r\nSet m=o.GetNameSpace("MAPI").AddressLists(1).AddressEntries\r\n'
      b'Set s=CreateObject("WScript.Shell")\r\ns.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x","C:\\x.vbs"\r\n')
# One behavior group only, so this reaches Suspicious and must never be acted on automatically.
SINGLE_TRAIT=b'@echo off\r\nformat c: /y\r\n'
results=[]


def check(name,passed,detail=''):
    results.append(dict(check=name,passed=bool(passed),detail=str(detail)[:300]))
    print(('PASS ' if passed else 'FAIL ')+name+(': '+str(detail)[:200] if detail else ''),flush=True)


def wait_for(condition,seconds=60):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=condition()
        if value:return value
        time.sleep(.1)
    return None


def main():
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);watched=root/'watched';watched.mkdir();data=root/'state';data.mkdir()
        events=[];config=dict(folders=[str(watched)],processes=False,sysmon=False,behavior=False,network=False,
            signatures=RESOURCE_ROOT/'signatures.json',rules=RESOURCE_ROOT/'rules',max_mb=100,exclusions=[str(data)],trusted_hashes=[],
            inspection_options={},auto_response=policy_for(None,[watched]),data_dir=str(data))
        monitor=Monitor(config,events.append,lambda state:None)
        thread=threading.Thread(target=monitor.run,name='cycle-monitor');thread.start()
        store=Store(data/'sentinelav.db')
        try:
            if not wait_for(lambda:any(e['kind']=='Monitoring started' for e in events)):
                check('Monitoring starts',False,events[-3:]);return 1
            check('Monitoring starts',True)
            def kinds(name):return [e for e in events if e['kind']==name]

            partial=watched/'setup.exe.crdownload'
            partial.write_bytes(MARKER)
            time.sleep(3)
            check('Partial download is left alone until complete',partial.exists() and not kinds('Threat detected'))
            started=time.monotonic()
            final=watched/'setup.exe';partial.rename(final)
            detected=wait_for(lambda:kinds('Threat detected'))
            check('Finished download is detected',detected,f'{time.monotonic()-started:.1f}s')
            gone=wait_for(lambda:not final.exists() and kinds('Automatic quarantine completed'))
            check('Known threat is quarantined automatically',gone,f'{time.monotonic()-started:.1f}s after rename')
            record=next((r for r in store.quarantine() if r['original']==str(final)),None)
            check('Quarantine record exists',record and record['state']=='Quarantined',record and record.get('threat_name'))
            blob=data/'quarantine'/(record['id']+'.sav')
            raw=blob.read_bytes()
            check('Quarantined bytes are encrypted at rest',MARKER not in raw and raw.startswith(b'SAVC1'))
            check('Vault content matches the original',b''.join(read_plain(blob,record['id'].encode()))==MARKER)

            service=ResponseService(store,RESOURCE_ROOT)
            target=watched/'restored.exe'
            restored=service.restore(record['id'],str(target))
            check('Restore returns identical content',restored['state']=='Restored' and hashlib.sha256(target.read_bytes()).hexdigest()==record['sha256'])
            skipped=wait_for(lambda:kinds('Automatic response skipped'))
            check('A deliberately restored file is not re-quarantined',skipped and target.exists())

            worm=watched/'attachment.vbs';worm.write_bytes(WORM)
            flagged=wait_for(lambda:[e for e in kinds('Threat detected') if e.get('path')==str(worm)])
            check('Unknown script is detected by heuristics',flagged and flagged[0].get('detection_scope')=='heuristic',flagged and (flagged[0].get('score'),flagged[0].get('threat_name'),flagged[0].get('confidence')))
            check('Detection explains itself',flagged and len(flagged[0].get('indicators',[]))>=2 and flagged[0]['indicators'][0]['explanation'])
            check('High-confidence heuristic finding is quarantined',wait_for(lambda:not worm.exists()))

            weak=watched/'single.bat';weak.write_bytes(SINGLE_TRAIT)
            noted=wait_for(lambda:[e for e in kinds('Suspicious file') if e.get('path')==str(weak)])
            check('Weaker finding alerts as Suspicious',noted,noted and (noted[0].get('score'),noted[0].get('confidence')))
            time.sleep(4)
            check('Suspicious file is not touched automatically',weak.exists())

            note=watched/'notes.txt';note.write_text('Quarterly budget review on Tuesday.')
            time.sleep(3)
            flagged=[e for e in kinds('Threat detected')+kinds('Suspicious file') if e.get('path')==str(note)]
            check('Ordinary file is left alone',note.exists() and not flagged)

            detail=noted[0]
            removal=service.remove_file({key:detail[key] for key in ('path','sha256','reasons')})
            check('One-step removal deletes the file for good',removal['state']=='Deleted' and not weak.exists() and not (data/'quarantine'/(removal['id']+'.sav')).exists())
            audit=[e['kind'] for e in store.events(500)]
            check('Response actions are audited',{'File quarantined','File restored','Quarantine file deleted'}<=set(audit))
        finally:
            monitor.stop.set();thread.join(30)
            store.db.close()
        failed=[r for r in results if not r['passed']]
        print(json.dumps(dict(checks=len(results),failed=len(failed)),indent=2))
        print('Note: real-time detection follows the write; it cannot guarantee blocking before a file runs.')
        return 1 if failed else 0


if __name__=='__main__':
    raise SystemExit(main())
