# Purpose: Reconcile interrupted guest ownership before any queue resume.
# Works with: lab.qualification.backend_hyperv, lab.qualification.backend_sandbox
# Used by: lab.qualification.backends

"""Owned guest lifecycle and bounded metadata transport. No writable host share."""
import json
from pathlib import Path
import uuid
from .backend_sandbox import Sandbox
from .backend_hyperv import HyperV

def reconcile(project,work,attempt):
    """Resume cannot requeue until every recorded owned environment is stopped."""
    path=Path(attempt)/'owner.json'
    if not path.exists():return
    if (Path(attempt)/'disposal.json').exists():
        r=json.loads((Path(attempt)/'disposal.json').read_text())
        if r.get('disposed') is True:return
    owner=json.loads(path.read_text())
    uuid.UUID(owner['guest_id'])
    if owner.get('backend') not in ('sandbox','hyperv'):raise ValueError('Unrecognized recorded backend')
    cls=Sandbox if owner['backend']=='sandbox' else HyperV
    backend=cls(project,work,attempt,lambda:False,lambda _:None);backend.owner=owner
    if isinstance(backend,HyperV) and backend.config['vm_id']!=owner['guest_id']:raise ValueError('Enrolled VM changed; recovery refused')
    backend.dispose()
