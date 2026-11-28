# Purpose: High-confidence and approved-hash quarantine policy. Never auto-terminates processes.
# Works with: data.change_journal, data.contracts, data.storage, detection.helpers.fusion, detection.inspection
# Used by: lab.qualification.guest_inventory, monitoring.core.monitor_loop, tests.unit.test_defense_layers,
#   tests.unit.test_runtime_guards

"""High-confidence and approved-hash quarantine policy. Never auto-terminates processes."""

from collections import deque
import os
from pathlib import Path
import queue
import re
import threading
import time
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService

DEFAULT_POLICY = dict(enabled=True, high_confidence=True, approved_hashes=[], roots=[])


def policy_for(saved, folders=()):
    """No saved choice means the default policy; a saved one is respected. High-confidence action defaults to the watched folders."""
    policy = dict(saved) if saved else dict(DEFAULT_POLICY)
    if policy.get('high_confidence') and not policy.get('roots'):
        policy['roots'] = [str(folder) for folder in folders][:32]
    return policy


def eligibility(event, policy):
    """Decide whether a detection may be quarantined automatically, without asking a person.

    Think of this as a long checklist where every item must pass. The finding has to come from a
    trusted verdict (an approved exact hash, a calibrated model policy, or a high-confidence
    malicious verdict), point at a real absolute path on a local drive, avoid symbolic links and
    junctions, and sit inside one of the folders the policy covers. The first failed check wins.

    Returns a pair (allowed, reason): allowed is True or False, and reason is a short sentence
    explaining the decision, suitable for showing to the user.
    """
    if not isinstance(policy, dict) or policy.get('enabled') is not True:
        return False, 'Policy disabled'
    if event.get('automatic_response_eligible') is False:
        return False, 'This finding requires manual response'
    digest = event.get('sha256', '')
    approvals = policy.get('approved_hashes', [])
    calibrated = (
        policy.get('allow_calibrated_unknown') is True
        and event.get('automatic_response_eligible') is True
        and isinstance(event.get('fusion_policy_id'), str)
        and bool(re.fullmatch('[0-9a-f]{64}', event['fusion_policy_id']))
    )
    high = (
        policy.get('high_confidence') is True
        and event.get('automatic_response_eligible') is True
        and event.get('verdict') == 'Malicious'
    )
    calibrated = calibrated or high
    if not calibrated and (
        not isinstance(approvals, list) or len(approvals) > 256 or digest not in approvals
    ):
        return False, 'Exact hash is not approved for automatic response'
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        return False, 'Invalid detection hash'
    if event.get('member_chain'):
        return False, 'Archive-member findings require manual review'
    if not calibrated and not any(
        reason.startswith('SHA-256: ') for reason in event.get('reasons', [])
    ):
        return False, 'An independent exact-hash signature match is required'
    raw_path = event.get('path', '')
    if not isinstance(raw_path, str) or not raw_path or not Path(raw_path).is_absolute():
        return False, 'Invalid absolute file path'
    original = Path(raw_path)
    if any(p.is_symlink() or p.is_junction() for p in [original, *original.parents]):
        return False, 'Linked paths require manual review'
    path = original.resolve()
    roots = policy.get('roots', [])
    if (
        not isinstance(roots, list)
        or not roots
        or len(roots) > 32
        or any(not isinstance(r, str) for r in roots)
    ):
        return False, 'No bounded response scope'
    if any(
        part.is_symlink() or part.is_junction()
        for root in roots
        for part in [Path(root), *Path(root).parents]
    ):
        return False, 'Linked response roots require manual review'
    if os.name == 'nt' and (len(path.drive) != 2 or path.drive[1] != ':'):
        return False, 'Automatic response supports local drives only'
    if not any(
        Path(root).is_absolute() and path.is_relative_to(Path(root).resolve()) for root in roots
    ):
        return False, 'Outside automatic-response scope'
    return True, (
        'High-confidence detection within configured scope'
        if high
        else 'Approved exact hash within configured scope'
    )


class AutoResponder:
    """Background worker that quarantines approved detections on its own.

    Detections are handed in with submit() and processed one at a time on a separate thread. Several
    safety brakes keep it from running away: a small queue, a limit of three actions per minute, a
    five-minute cooldown per file, and a circuit breaker that pauses everything after three failures
    in a row. It never kills processes; it only moves files into quarantine.
    """

    def __init__(self, data_dir, root, policy, emit):
        """Remember the settings and start the worker thread straight away.

        data_dir holds the database, root is the installation folder, policy is the starting
        response policy, and emit is a callback that receives event dictionaries for the activity
        log.
        """
        self.data_dir = Path(data_dir)
        self.root = Path(root)
        self.policy = policy
        self.emit = emit
        self.queue = queue.Queue(maxsize=8)
        self.stopping = threading.Event()
        self.attempts = deque()
        self.seen = {}
        self.ready = False
        self.enabled = False
        self.failures = 0
        self.circuit_open = False
        self.reset_id = None
        self.error = ''
        self.thread = threading.Thread(target=self.run, name='approved-hash-quarantine')
        self.thread.start()

    def report(self, kind, details, level='Info'):
        """Send one entry to the activity log through the emit callback."""
        self.emit(
            dict(
                time=time.strftime('%Y-%m-%d %H:%M:%S'),
                kind=kind,
                details=details,
                source='Response policy',
                level=level,
            )
        )

    def submit(self, detection):
        """Queue a detection for automatic quarantine if the policy allows it.

        Ineligible findings are silently ignored (they stay for manual review). If the queue is
        full, a warning is logged instead of blocking the caller.
        """
        allowed, _ = eligibility(detection, self.policy)
        if not allowed or self.stopping.is_set():
            return
        try:
            self.queue.put_nowait(dict(detection))
        except queue.Full:
            self.report(
                'Automatic response backlog',
                'Queue full; finding left for manual review',
                'Warning',
            )

    def run(self):
        """Main loop of the worker thread.

        Opens its own database connection, then repeatedly: reloads the latest saved policy, takes
        the next queued detection, re-checks eligibility, applies the rate limits, and finally
        quarantines the file. Any unexpected error stops the worker and is reported.
        """
        store = None
        try:
            store = Store(self.data_dir / 'sentinelav.db')
            responder = ResponseService(store, self.root)
            self.ready = True
            while not self.stopping.is_set():
                # Re-read the saved policy every round, so changes made in the settings page take
                # effect without a restart.
                latest = (
                    policy_for(store.get('auto_response', None), self.policy.get('roots', []))
                    if self.policy.get('high_confidence')
                    else store.get('auto_response', {})
                )
                # Saving the policy again gives it a new reset_id; that is how a person clears a
                # tripped circuit breaker.
                if isinstance(latest, dict) and latest.get('reset_id') != self.reset_id:
                    self.reset_id = latest.get('reset_id')
                    self.failures = 0
                    self.circuit_open = False
                self.enabled = (
                    isinstance(latest, dict)
                    and latest.get('enabled') is True
                    and not self.circuit_open
                )
                try:
                    detection = self.queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                allowed, reason = eligibility(detection, latest)
                if not allowed or self.circuit_open:
                    continue
                now = time.monotonic()
                key = (detection['path'], detection['sha256'])
                # Rate limiting: forget attempts older than a minute, then refuse if three already
                # happened, or if this same file was handled in the last five minutes.
                self.attempts = deque(t for t in self.attempts if now - t < 60)
                if len(self.attempts) >= 3 or now - self.seen.get(key, -1000) < 300:
                    self.report(
                        'Automatic response deferred',
                        'Rate limit/cooldown reached; review finding manually',
                        'Warning',
                    )
                    continue
                self.attempts.append(now)
                self.seen[key] = now
                if len(self.seen) > 1024:
                    self.seen.pop(next(iter(self.seen)))
                # A file someone deliberately restored stays with them; it must not bounce straight back into quarantine.
                if any(
                    item['sha256'] == detection['sha256'] and item['state'] == 'Restored'
                    for item in store.quarantine()
                ):
                    self.report(
                        'Automatic response skipped',
                        'This file was restored by a person; review it manually: '
                        + detection['path'],
                        'Warning',
                    )
                    continue
                try:
                    # Clean up autorun entries first, while the file is still in place to be matched
                    # against them.
                    self.persistence(detection, latest, store, responder)
                    record = responder.quarantine_file(
                        detection,
                        require_automatic=detection.get('verdict') == 'Malicious'
                        and latest.get('high_confidence') is True
                        and detection['sha256'] not in latest.get('approved_hashes', []),
                    )
                    self.failures = 0
                    self.report('Automatic quarantine completed', str(record['original']))
                except Exception as error:
                    self.report('Automatic response failed', str(error), 'Warning')
                    self.failures += 1
                    # Circuit breaker: three failures in a row usually mean something is wrong with
                    # the environment, so stop acting until someone looks.
                    if self.failures >= 3:
                        self.circuit_open = True
                        self.enabled = False
                        self.report(
                            'Automatic response paused',
                            'Three consecutive failures; review the cause and save the response policy to reset.',
                            'Warning',
                        )
        except Exception as error:
            self.error = str(error)
            self.report('Automatic response unavailable', self.error, 'Warning')
        finally:
            self.ready = False
            self.enabled = False
            if store:
                store.db.close()

    def close(self):
        """Ask the worker to stop and wait until it has really finished."""
        self.stopping.set()
        # Fresh verification/response is bounded by the isolated scan worker;
        # do not report monitoring stopped while an owned action is unfinished.
        self.thread.join()

    def persistence(self, detection, policy, store, responder):
        """Undo recent autorun registry entries that point at the detected file.

        Malware often adds itself to the current user's Run keys so it starts again at the next
        logon. When this optional feature is on, we look for verified registry changes from the last
        minute that reference the detected file, plan a cleanup, and carry it out. Each change is
        re-verified by a fresh scan before anything is undone. It quietly does nothing when the
        feature is off or the signed policy does not permit automatic action.
        """
        if not policy.get('auto_persistence') or not store.get('watch_app_changes', False):
            return
        from sentinelav.updates.artifacts import active
        from sentinelav.detection.helpers.fusion import gates
        from sentinelav.data.contracts import fingerprint
        from sentinelav.data.change_journal import ChangeJournal
        from sentinelav.response.remediation import (
            Remediator,
            WindowsRemediationBackend,
            referenced_paths,
        )

        options = store.get('inspection_options', {})
        folder = options.get('analysis_store', str(store.path.parent / 'analysis-data'))
        trust = options.get('analysis_trust', str(self.root / 'trusted-update-keys.json'))
        # Automatic cleanup is only allowed when the active, signed detection policy says so.
        signed, _ = active(folder, trust, 'policy')
        if not gates(signed)['automatic']:
            return
        if detection.get('fusion_policy_id') and detection['fusion_policy_id'] != fingerprint(
            signed
        ):
            raise ValueError('Automatic persistence policy changed')
        journal = ChangeJournal(self.data_dir / 'app-changes')
        try:
            # Collect up to 16 matching changes: verified, current-user registry edits made in the
            # last 60 seconds that reference the detected file.
            selected = []
            for record in journal.changes():
                resource = record['resource']
                if (
                    resource['kind'] != 'registry'
                    or resource.get('hive') != 'HKCU'
                    or record['attribution'] != 'Verified'
                ):
                    continue
                if not 0 <= time.time() - record['observed_at'] <= 60:
                    continue
                if any(
                    os.path.normcase(str(Path(path).resolve()))
                    == os.path.normcase(str(Path(detection['path']).resolve()))
                    for path in referenced_paths(record)
                ):
                    selected.append(record['id'])
                if len(selected) >= 16:
                    break
            if not selected:
                return
            from sentinelav.detection.inspection import IsolatedScanner

            scanner = IsolatedScanner(
                self.root / 'signatures.json', self.root / 'rules', options=options, persistent=True
            )
            try:

                def verify(path):
                    """Re-scan one file and return its detections."""
                    return scanner.scan([path], lambda: False, lambda *a: None)['detections']

                # The remediator re-scans each referenced file with verify() before undoing
                # anything, so a clean file is never touched.
                engine = Remediator(journal, WindowsRemediationBackend(), verify, responder)
                plan = engine.plan(selected, with_related=False)
                plan.update(automatic=True, authorized_policy=fingerprint(signed))
                journal.operation(plan)
                receipt = engine.execute(plan['id'], approved=True)
                self.report(
                    'Automatic persistence cleanup',
                    receipt['state'],
                    (
                        'Info'
                        if all(r['state'] == 'Verified' for r in receipt['results'])
                        else 'Warning'
                    ),
                )
            finally:
                scanner.close()
        finally:
            journal.close()
