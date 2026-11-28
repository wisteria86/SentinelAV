# Purpose: Versioned evidence contracts shared by tracking and remediation.
# Works with: sibling modules in data
# Used by: data.change_journal, detection.helpers.fusion, detection.helpers.pe_ensemble, detection.core.scan_flow

"""Versioned evidence contracts shared by tracking and remediation."""

import hashlib
import json
import time
import uuid

SCHEMA = 1
ATTRIBUTIONS = {'Verified', 'Correlated', 'Unattributed'}
KINDS = {'registry', 'startup_file', 'task', 'service', 'setting_file'}


def canonical(value):
    """Encode a value as compact, sorted JSON bytes, so the same data always gives exactly the same
    bytes (and therefore the same hash).
    """
    return json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False
    ).encode()


def fingerprint(value):
    """Return the SHA-256 hash of a value's canonical JSON form, used as a stable identity."""
    return hashlib.sha256(canonical(value)).hexdigest()


def change_record(
    resource, before, after, *, baseline=False, attribution='Unattributed', process=None
):
    """Build a new change record describing how a resource went from `before` to `after`.

    The record carries hashes of both states so later tampering can be detected. `attribution` says
    how sure we are about who made the change; 'Verified' is only allowed when we know the exact
    writing process (its id and start time). `baseline` marks changes that already existed when
    monitoring started.
    """
    if resource.get('kind') not in KINDS or not resource.get('id'):
        raise ValueError('Unsupported change resource')
    if attribution not in ATTRIBUTIONS:
        raise ValueError('Invalid attribution')
    if attribution == 'Verified' and (
        not process or not process.get('pid') or not process.get('creation')
    ):
        raise ValueError('Verified attribution needs a creation-time-verified writer')
    return dict(
        schema=SCHEMA,
        id=uuid.uuid4().hex,
        observed_at=time.time(),
        resource=resource,
        before=before,
        after=after,
        before_hash=fingerprint(before),
        after_hash=fingerprint(after),
        baseline_available=not baseline,
        preexisting=baseline,
        attribution=attribution,
        process=process,
        baseline_trusted=False,
    )


def validate_change(record):
    """Check that a change record is well formed and that its hashes still match its contents, then
    return it unchanged. Raises ValueError otherwise.
    """
    if record.get('schema') != SCHEMA or record.get('attribution') not in ATTRIBUTIONS:
        raise ValueError('Invalid change schema')
    if record.get('resource', {}).get('kind') not in KINDS:
        raise ValueError('Unsupported resource')
    for side in ('before', 'after'):
        if record.get(side + '_hash') != fingerprint(record.get(side)):
            raise ValueError('Change integrity mismatch')
    if record['attribution'] == 'Verified' and (
        not record.get('process')
        or not record['process'].get('pid')
        or not record['process'].get('creation')
    ):
        raise ValueError('Verified attribution lacks process identity')
    return record


def analysis_result(report, options, versions):
    """Add a stable envelope without breaking existing history consumers."""
    detected = bool(report.get('detections'))
    decision = report.get('decision', {})
    return dict(
        schema=1,
        kind='AnalysisResult',
        verdict=(
            'Detected'
            if detected
            else decision.get(
                'verdict',
                'Indeterminate' if report.get('errors') or report.get('skipped') else 'No match',
            )
        ),
        coverage=dict(
            status=report['status'],
            enabled=dict(options),
            scanned=report.get('scanned', 0),
            skipped=report.get('skipped', 0),
        ),
        evidence=decision.get('evidence', []),
        omissions=list(report.get('errors', [])),
        versions=versions,
        timings=dict(elapsed_seconds=report.get('elapsed', 0)),
    )
