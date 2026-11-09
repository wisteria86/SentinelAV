# Purpose: Encrypted, owner-readable views of service-owned change records.
# Works with: data.contracts, platform.integrity, platform.windows_identity, platform.windows_service,
#   response.response
# Used by: monitoring.change_monitor, platform.remediation_broker, ui.app_changes_ui,
#   tests.unit.test_remediation_broker

"""Encrypted, owner-readable views of service-owned change records.

Machine DPAPI bridges LocalService to the configured account. Protected ACLs
remain mandatory: other accounts must not be granted access to these blobs.
"""
import json
import os
from pathlib import Path
import time
import uuid
from sentinelav.data.contracts import canonical,validate_change
from sentinelav.platform.integrity import verify_windows_acl
from sentinelav.response.response import dpapi
from sentinelav.workspace import unlinked

MAX_VIEW=4*1024*1024


def publish_view(folder,journal,owner,errors):
    rows=[];used=0;truncated=False
    for row in journal.changes(500):
        size=len(canonical(row))
        if used+size>MAX_VIEW-65536:truncated=True;continue
        rows.append(row);used+=size
    view=dict(schema=1,owner_sid=owner,generated=time.time(),rows=rows,receipts=[],
        errors=list(errors)+(['History view truncated; older records remain in the protected journal'] if truncated else []),
        scope='Machine Run entries, common Startup, non-Microsoft tasks and services; user tracking is separate')
    target=unlinked(Path(folder)/'app-changes-view.bin');pending=unlinked(target.with_name('view-'+uuid.uuid4().hex+'.pending'))
    try:
        with pending.open('xb') as stream:
            stream.write(dpapi(canonical(view),machine=True));stream.flush();os.fsync(stream.fileno())
        os.replace(pending,target)
    finally:pending.unlink(missing_ok=True)


def load_view(fresh=False):
    from sentinelav.platform.windows_service import service_paths
    from sentinelav.platform.windows_identity import current_sid
    base,data=service_paths();target=unlinked(data/'app-changes-view.bin')
    for path in (base,data,target):verify_windows_acl(path,service_writable=True)
    with target.open('rb') as stream:raw=stream.read(MAX_VIEW+65537)
    if len(raw)>MAX_VIEW+65536:raise ValueError('Service history exceeds transport budget')
    view=json.loads(dpapi(raw,True))
    if view.get('schema')!=1 or view.get('owner_sid')!=current_sid():raise ValueError('Service history belongs to a different deployment owner')
    age=time.time()-view['generated']
    if age< -5 or (fresh and age>90):raise ValueError('Protected service history is stale; start or refresh service monitoring')
    for row in view['rows']:validate_change(row)
    view['stale']=age>90
    return view
