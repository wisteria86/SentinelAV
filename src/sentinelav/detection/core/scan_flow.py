# Purpose: Walk scan roots and assemble bounded per-file analysis results.
# Works with: data.contracts, detection.core.archive_inspection, detection.helpers.decisions, detection.core.file_analysis,
#   platform.amsi_client
# Used by: detection.engine

"""Read-only detection engine, independent of Qt. Never executes inspected files."""

import hashlib
import os
import time
from pathlib import Path
from sentinelav.detection.core.archive_inspection import inspect_archive, vouched_members
from sentinelav.detection.core.file_analysis import parse_object, public_fields
from sentinelav.detection.helpers.file_types import classify
from sentinelav.detection.helpers.threat_score import indicator

MAX_ERRORS = 2000
# Standing format limits describe every file of a type. They stay in the decision record but do not make a scan incomplete.
STANDING_LIMITS = (
    'VBA source inspection does not',
    'PDF partial inspection',
    'HTML scripts inspected as text',
    'RTF partial extraction',
    'External script was not fetched',
)
SCRIPT_AMSI = ('.ps1', '.psm1', '.js', '.vbs', '.hta')


class BoundedErrors(list):
    """Keeps a full-disk scan's report transportable while still counting everything dropped."""

    dropped = 0

    def append(self, value):
        """Add one error message (trimmed), or just count it once the list is full."""
        if len(self) >= MAX_ERRORS:
            self.dropped += 1
        else:
            super().append(str(value)[:1200])

    def extend(self, values):
        """Add several error messages, one at a time, through append()."""
        for value in values:
            self.append(value)


class ScanFlowMixin:
    """The part of the Scanner that walks folders, reads each file safely and hands it on for analysis."""

    def scan(self, roots, cancelled, progress, skip=0):
        """Scan every file under the given roots and return a full result dictionary.

        Folders are walked without following links, excluded paths are skipped, each file is read
        once into memory and hashed, and the file is re-checked afterwards to make sure it did not
        change while being read. progress(path, scanned, threats) is called after each file, and
        cancelled() is checked often so the scan can stop quickly. skip lets a restarted worker
        continue after the file that stopped the previous one.

        When the scan target is a single file, the result also carries a detailed decision and the
        file's identity.
        """
        result = dict(
            started=time.strftime('%Y-%m-%d %H:%M:%S'),
            scanned=0,
            skipped=0,
            errors=BoundedErrors(),
            detections=[],
            suspicious=[],
            status='Complete',
            elapsed=0,
            structural_review=[],
            structural_review_total=0,
            advanced_reviews=[],
            advanced_review_total=0,
            suspicious_total=0,
            detections_total=0,
            walked=skip,
        )
        start = time.monotonic()
        self.current_scan_result = result
        seen = set()
        capture_identity = len(roots) == 1 and Path(roots[0]).is_file()
        if not roots:
            result['errors'].append('No scan locations were selected or available')

        def walk(root):
            """Yield every file under one root, sorted, without following symbolic links or junctions."""
            if root.is_symlink() or root.is_junction():
                result['errors'].append(f'Linked scan root was not followed: {root}')
                return
            if self.excluded(root):
                return
            if root.is_file():
                yield root
            elif root.is_dir():

                def onerror(error):
                    """Record a folder that could not be listed instead of stopping the walk."""
                    result['errors'].append(str(error))

                for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
                    if cancelled():
                        return
                    dirs[:] = sorted(
                        d
                        for d in dirs
                        if not (Path(directory) / d).is_symlink()
                        and not (Path(directory) / d).is_junction()
                        and not self.excluded(Path(directory) / d)
                    )
                    for name in sorted(files):
                        yield Path(directory) / name
            else:
                result['errors'].append(f'Unavailable path: {root}')

        index = 0
        for root in roots:
            for path in walk(Path(root)):
                if cancelled():
                    break
                index += 1
                # A restarted worker resumes after the file that stopped the previous one.
                if index <= skip:
                    continue
                result['walked'] = index
                started = getattr(self, 'file_started', None)
                if started:
                    started(index, str(path))
                try:
                    resolved = path.resolve()
                    if resolved in seen or path.is_symlink() or self.excluded(path):
                        continue
                    seen.add(resolved)
                    self.current_parent = str(resolved)
                    self.member_seen = set()
                    self.member_bytes = 0
                    if path.stat().st_size > self.max_bytes:
                        self.inspect_oversized(path, resolved, result, capture_identity, cancelled)
                        progress(str(path), result['scanned'], len(result['detections']))
                        continue
                    digest = hashlib.sha256()
                    data = bytearray()
                    with path.open('rb') as stream:
                        initial = os.fstat(stream.fileno())
                        while chunk := stream.read(1024 * 1024):
                            if cancelled():
                                break
                            data.extend(chunk)
                            if len(data) > self.max_bytes:
                                raise ValueError('File grew beyond size limit')
                            digest.update(chunk)
                        final = os.fstat(stream.fileno())
                    if cancelled():
                        break
                    current = path.stat()
                    # Windows fstat/stat disagree about ctime on rewritten files;
                    # compare ctime only within the same descriptor API.
                    identity = lambda value: (
                        value.st_dev,
                        value.st_ino,
                        value.st_size,
                        value.st_mtime_ns,
                    )
                    # Compare the file's identity before reading, after reading and now; any
                    # difference means it was being changed.
                    if (
                        identity(initial) != identity(final)
                        or identity(initial) != identity(current)
                        or initial.st_ctime_ns != final.st_ctime_ns
                        or len(data) != initial.st_size
                    ):
                        raise ValueError('File changed during inspection; scan it again')
                    sha = digest.hexdigest()
                    self.current_parent_sha = sha
                    if capture_identity:
                        result['file_identity'] = dict(
                            path=str(resolved),
                            sha256=sha,
                            stat=[str(value) for value in identity(current)],
                        )
                    if sha in self.trusted_hashes:
                        result['scanned'] += 1
                        continue
                    self.inspect_file(
                        data, path, resolved, sha, result, capture_identity, cancelled
                    )
                except OSError as error:
                    # Windows answers EINVAL when another security product blocks a read it considers infected.
                    blocked = getattr(error, 'errno', None) == 22 and getattr(
                        error, 'winerror', None
                    ) in (225, None)
                    result['errors'].append(
                        f'{path}: Read blocked, likely by another security product such as Microsoft Defender'
                        if blocked
                        else f'{path}: {error}'
                    )
                except Exception as error:
                    result['errors'].append(f'{path}: {error}')
                self.send_suspicious(result)
                progress(str(path), result['scanned'], len(result['detections']))
            if cancelled():
                break
        result['errors_omitted'] = result['errors'].dropped
        result['errors'] = list(result['errors'])
        if cancelled():
            result['status'] = 'Cancelled'
        elif result['errors'] or result['skipped']:
            result['status'] = 'Complete with omissions'
        else:
            result['status'] = 'Complete'
        result['elapsed'] = round(time.monotonic() - start, 2)
        if capture_identity:
            from sentinelav.detection.helpers.decisions import Evidence, decide

            facts = []
            for finding in result['detections']:
                if (
                    finding.get('detection_scope') == 'derived content'
                    or finding.get('detection_scope') == 'heuristic'
                ):
                    continue
                for reason in finding['reasons']:
                    if 'SHA-256: ' in reason:
                        source = 'hash'
                    elif 'YARA: ' in reason:
                        source = 'yara'
                    elif 'AMSI: ' in reason:
                        source = 'amsi'
                    else:
                        source = 'eicar'
                    facts.append(Evidence(source, 'signature_match', reason, confirmed=True))
            facts.extend(
                Evidence('static', s['code'], s['explanation'])
                for s in result.get('static_analysis', {}).get('signals', [])
            )
            facts.extend(
                Evidence(**item) for item in result.get('advanced_analysis', {}).get('evidence', [])
            )
            result['decision'] = decide(facts, result['errors'])
        result['warnings'] = list(
            dict.fromkeys(self.warnings + (self.advanced.omissions if self.advanced else []))
        )
        result['yara'] = self.rule_summary
        result['signature_policy'] = dict(
            signature_free=self.options['signature_free'],
            hashes=not self.options['signature_free'],
            yara=not self.options['signature_free'],
            test_markers=not self.options['signature_free'],
            amsi=self.options['amsi'],
            reputation=self.options['reputation'],
        )
        from sentinelav import __version__
        from sentinelav.data.contracts import analysis_result

        result['analysis_result'] = analysis_result(
            result,
            self.options,
            dict(engine=__version__, signatures=self.signatures.metadata, yara=self.rule_summary),
        )
        return result

    def inspect_file(self, data, path, resolved, sha, result, capture_identity, cancelled):
        # Preserve an independently verified exact-hash finding
        # even if a subsequent native parser fails in the worker.
        """Run every detection layer on one file that has already been read into memory, and record its
        findings.

        The steps are: signature checks, file-type and structure analysis, optional AMSI, the
        advanced pipeline, recursive archive inspection, and finally the combined score. Results go
        into `result` as detections (malicious) or suspicious findings.
        """
        early_label = self.signatures.get(sha)
        if early_label is not None and getattr(self, 'early_finding', None):
            self.early_finding(
                dict(
                    path=str(resolved),
                    sha256=sha,
                    reasons=['SHA-256: ' + early_label],
                    yara_matches=[],
                )
            )
        names, yara_matches, inspection_errors = self.analyze_bytes(data, sha)
        result['errors'].extend(f'{path}: {error}' for error in inspection_errors)
        file_type = classify(data, path.suffix)
        format_info, analysis, malformed = parse_object(data, file_type)
        if malformed:
            result['errors'].append(f'{path}: PE metadata inspection: {malformed}')
        if analysis['imports']['status'] in ('Incomplete', 'Unavailable'):
            result['errors'].append(
                f"{path}: PE import inspection: {analysis['imports'].get('reason','Unavailable')}"
            )
        if analysis['delay_imports']['status'] == 'Incomplete':
            result['errors'].append(
                f"{path}: PE delay imports: {analysis['delay_imports']['reason']}"
            )
        for omission in analysis.get('image_details', {}).get('omissions', []):
            if 'budget' not in omission.casefold():
                result['errors'].append(f'{path}: PE details: ' + omission)
        if capture_identity:
            result['file_format'] = format_info
            result['static_analysis'] = analysis
        if analysis['signals']:
            result['structural_review_total'] += 1
            # Bound worker transport for folder scans. These raw traits feed the score below.
            if len(result['structural_review']) < 100:
                result['structural_review'].append(
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        **{
                            k: v
                            for k, v in analysis.items()
                            if k not in ('imports', 'delay_imports')
                        },
                    )
                )
        if self.options['amsi'] and path.suffix.lower() in SCRIPT_AMSI:
            try:
                from sentinelav.platform.amsi_client import scan_buffer

                amsi = scan_buffer(bytes(data), path.name)
                if amsi['detected'] or amsi['blocked_by_policy']:
                    names.append('AMSI: installed provider detection/policy block')
            except Exception as error:
                result['errors'].append(f'{path}: AMSI unavailable: {error}')
        result['scanned'] += 1
        rows = []
        if names:
            rows.append(
                dict(path=str(resolved), sha256=sha, reasons=names, yara_matches=yara_matches)
            )
        decision = None
        if self.advanced:
            decision = self.advanced.inspect(
                data,
                path,
                sha,
                analysis,
                format_info,
                self.analyze_member,
                cancelled,
                emulation=self.options['emulation'],
            )
            if capture_identity:
                result['advanced_analysis'] = decision
            derived = [e for e in decision['evidence'] if e.get('confirmed')]
            reasons = []
            for item in derived:
                reasons.extend(
                    'Analyzed content (' + item['source'] + '): ' + reason
                    for reason in item.get('details', {}).get('reasons', [])
                )
            if reasons:
                rows.append(
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        reasons=reasons,
                        yara_matches=[],
                        analysis_evidence=derived,
                        detection_scope='derived content',
                        fusion_policy_id=decision.get('fusion_policy_id'),
                    )
                )
            if decision['verdict'] == 'Review':
                result['advanced_review_total'] += 1
                if len(result['advanced_reviews']) < 50:
                    result['advanced_reviews'].append(
                        dict(
                            path=str(resolved),
                            sha256=sha,
                            reasons=[e['description'] for e in decision['evidence'][:16]],
                            omissions=decision['omissions'][:8],
                            automatic_response_eligible=False,
                        )
                    )
            # An unavailable model affects the whole scan, so it is one engine warning rather than an error on every file.
            coverage = [
                item
                for item in decision['omissions']
                if not item.startswith(STANDING_LIMITS) and item not in self.advanced.omissions
            ]
            if coverage:
                result['errors'].append(
                    f'{path}: Advanced analysis omissions: ' + '; '.join(coverage)[:1200]
                )
        nested = []
        encrypted = []
        bomb = False
        if self.options['archives']:
            nested, omissions, archive_stats = inspect_archive(
                bytes(data), self.assess_member, cancelled
            )
            nested = vouched_members(nested, resolved, data)
            result['archive_entries_seen'] = (
                result.get('archive_entries_seen', 0) + archive_stats['entries']
            )
            result['archive_bytes_expanded'] = (
                result.get('archive_bytes_expanded', 0) + archive_stats['expanded']
            )
            result['errors'].extend(
                f'{path}: {error}'
                for error in omissions
                if not any(limit in error for limit in STANDING_LIMITS)
            )
            encrypted = archive_stats['encrypted_executables']
            bomb = archive_stats['bomb']
        extra = []
        if encrypted:
            extra.append(
                indicator(
                    'encrypted_archive_with_program',
                    'evasion',
                    15,
                    'A password-protected archive holds a program or script that could not be inspected.',
                    category='Dropper',
                    evidence=encrypted[0],
                )
            )
        if bomb:
            extra.append(
                indicator(
                    'decompression_bomb',
                    'evasion',
                    25,
                    'The archive expands far beyond a normal ratio, a technique used to exhaust scanners.',
                    category='Evasion',
                )
            )
        assessed = self.assess_object(
            data,
            path.suffix,
            names,
            yara_matches,
            path=str(resolved),
            decision=decision,
            metadata=format_info,
            analysis=analysis,
            malformed=malformed,
            extra=extra,
        )
        result['errors'].extend(
            f'{path}: {error}'
            for error in assessed['omissions']
            if not error.startswith(STANDING_LIMITS)
        )
        fields = public_fields(assessed)
        for row in rows:
            # A match found only in decoded content keeps the decision's own authority, so quoted text cannot trigger removal.
            derived_authority = (
                decision.get('automatic_response_eligible', False)
                if row.get('detection_scope') == 'derived content'
                else None
            )
            row.update(fields)
            if derived_authority is not None:
                row['automatic_response_eligible'] = derived_authority
            self.add_finding(result, 'detections', row)
        top = assessed
        arms = dict(assessed.get('arms') or {})
        for finding in nested:
            member = finding.pop('assessment') or {}
            label = '!/'.join(finding['member_chain'])
            member_fields = public_fields(member) if member else {}
            if finding['reasons'] or member.get('verdict') == 'Malicious':
                reasons = finding['reasons'] or member.get('reasons', [])
                self.add_finding(
                    result,
                    'detections',
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        **{**member_fields, 'automatic_response_eligible': False},
                        **{key: value for key, value in finding.items() if key != 'reasons'},
                        reasons=['Archive member: ' + label + ' — ' + reason for reason in reasons],
                    ),
                )
            elif member.get('verdict') == 'Suspicious':
                self.add_finding(
                    result,
                    'suspicious',
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        **{**member_fields, 'automatic_response_eligible': False},
                        **{key: value for key, value in finding.items() if key != 'reasons'},
                        reasons=[
                            'Archive member: ' + label + ' — ' + reason
                            for reason in member.get('reasons', [])
                        ],
                    ),
                )
            if member and member.get('score', 0) > top.get('score', 0):
                top = member
            # Each evaluation arm keeps its own strongest object, so a hash on the container cannot hide what its members show.
            for arm, value in (member.get('arms') or {}).items():
                if arm not in arms or value['score'] > arms[arm]['score']:
                    arms[arm] = value
        if not rows:
            if assessed['verdict'] == 'Malicious':
                self.add_finding(
                    result,
                    'detections',
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        reasons=assessed['reasons'],
                        yara_matches=[m for m in yara_matches if m.get('scope') == 'generic'],
                        detection_scope='heuristic',
                        **fields,
                    ),
                )
            elif assessed['verdict'] == 'Suspicious':
                self.add_finding(
                    result,
                    'suspicious',
                    dict(
                        path=str(resolved),
                        sha256=sha,
                        reasons=assessed['reasons'],
                        yara_matches=[m for m in yara_matches if m.get('scope') == 'generic'],
                        detection_scope='heuristic',
                        **fields,
                    ),
                )
        if capture_identity:
            result['assessment'] = {
                **public_fields(top),
                'arms': arms,
                'reasons': top.get('reasons', []),
                'analyzed': assessed['analyzed'],
                'inert': assessed['inert'],
                'file_kind': assessed['file_kind'],
            }
