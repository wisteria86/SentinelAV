# Purpose: Headless Quick, Full and custom scans for scripts, documentation and tests.
# Works with: data.storage, detection.inspection, detection.scan_targets, paths
# Used by: entrypoint

"""Headless Quick, Full and custom scans. Reports only; nothing is quarantined from here."""
import json
from pathlib import Path
import sys

from sentinelav.paths import RESOURCE_ROOT


def summary(result):
    def row(finding):
        return {key:finding.get(key) for key in ('path','verdict','score','confidence','threat_name','reasons','member_chain','sha256') if key in finding}
    return dict(status=result['status'],scanned=result['scanned'],skipped=result['skipped'],elapsed=result['elapsed'],
        detections=[row(item) for item in result['detections']],suspicious=[row(item) for item in result.get('suspicious',[])],
        omissions=len(result['errors'])+result.get('errors_omitted',0),first_omissions=result['errors'][:20],warnings=result.get('warnings',[]))


def run(target,data_dir):
    """Exit code 0 means nothing flagged, 1 means findings, 2 means the scan could not run."""
    from sentinelav.data.storage import Store
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.detection.scan_targets import targets
    named=target.casefold()
    if named in ('quick','full'):roots,kind=targets(named.capitalize()),named.capitalize()+' Scan'
    else:
        path=Path(target)
        if not path.is_absolute() or not path.exists():
            print('Scan target must be quick, full, or an existing absolute path',file=sys.stderr)
            return 2
        roots,kind=[path],'Custom Folder'
    Path(data_dir).mkdir(parents=True,exist_ok=True)
    store=Store(Path(data_dir)/'sentinelav.db')
    from sentinelav.detection.clamav_engine import ensure_service
    _,problem=ensure_service(store.get('inspection_options',{}).get('clamav',True))
    if problem:print('ClamAV unavailable: '+problem,file=sys.stderr)
    try:
        scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',store.get('max_mb',100),
            store.get('exclusions',[])+[str(store.path.parent)],store.get('trusted_hashes',[]),store.get('inspection_options',{}))
        result=scanner.scan(roots,lambda:False,lambda *args:None)
        result['kind']=kind
        store.save_scan(result)
    finally:
        store.db.close()
    print(json.dumps(summary(result),indent=2))
    return 1 if result['detections'] or result.get('suspicious') else 0
