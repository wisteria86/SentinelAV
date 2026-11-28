# Purpose: Read-only detection engine, independent of Qt. Never executes inspected files.
# Works with: detection.advanced_pipeline, detection.archive_inspection, detection.file_formats,
#   detection.scan_flow, detection.signature_db
# Used by: detection.inspection_worker, entrypoint, lab.lab, tests.unit.test_amsi_buffers

"""Read-only detection engine, independent of Qt. Never executes inspected files."""

import hashlib
import json
import os
import time
from pathlib import Path
from sentinelav.detection.signature_db import SignatureIndex
from sentinelav.detection.yara_rules import compile_rules, evidence
from sentinelav.detection.archive_inspection import inspect_zip

MIN_HASH_BYTES = 1


class DisabledSignatures:
    """Stand-in for the signature database when scanning in signature-free mode: it never matches
    anything.
    """

    metadata = dict(status='Disabled', reason='Signature-free evaluation', count=0)

    def __len__(self):
        """There are no signatures."""
        return 0

    def get(self, sha):
        """Never find a match."""
        return None

    def close(self):
        """Nothing to close."""
        pass


from .file_analysis import FileAnalysisMixin
from .scan_flow import ScanFlowMixin


class Scanner(ScanFlowMixin, FileAnalysisMixin):
    """The core file scanner. It reads files and checks them against every detection layer; it never
    runs them.

    The layers are: exact hash lists (SHA-256 and optionally MD5), YARA rules (our own plus optional
    third-party rule packs), ClamAV, and, when enabled, the advanced pipeline (models, decoders,
    emulation). The scanning loop itself lives in ScanFlowMixin and the scoring of each file in
    FileAnalysisMixin; this class sets everything up and provides the byte-level checks.
    """

    def __init__(
        self, signatures, rules_dir, max_mb=100, exclusions=(), trusted_hashes=(), options=None
    ):
        """Load every enabled detection layer.

        signatures is the hash database, rules_dir the folder of YARA rules, and max_mb the largest
        file read in full. exclusions are folders to skip, trusted_hashes are files a person has
        marked as safe, and options switches the individual layers on or off.
        """
        from sentinelav.platform.engine_policy import inspection_options

        self.options = inspection_options(options)
        strict = self.options['signature_free']
        self.signatures = DisabledSignatures() if strict else SignatureIndex(signatures)
        self.max_bytes = max_mb * 1024 * 1024
        self.exclusions = [Path(p).resolve() for p in exclusions]
        self.trusted_hashes = set() if strict else set(trusted_hashes)
        if strict:
            self.rules, self.rule_summary, self.rule_metadata = (
                None,
                dict(status='Disabled', warnings=[], reason='Signature-free evaluation'),
                {},
            )
        else:
            self.rules, self.rule_summary, self.rule_metadata = compile_rules(rules_dir)
        self.warnings = list(self.rule_summary['warnings'])
        self.advanced = None
        if self.options['advanced']:
            from sentinelav.detection.advanced_pipeline import AdvancedPipeline

            self.advanced = AdvancedPipeline(self.options.get('analysis_store'), self.options)
        self.packs = []
        if self.options['rule_packs']:
            from sentinelav.detection.rule_packs import load_packs

            self.packs, problems = load_packs()
            self.warnings.extend(problems)
        self.md5 = None
        if self.options['md5_feed']:
            from sentinelav.detection.md5_feed import Md5Feed

            try:
                self.md5 = Md5Feed()
            except FileNotFoundError:
                pass
            except Exception as error:
                self.warnings.append('MD5 hash list unavailable: ' + str(error)[:120])
        self.clamav = None
        if self.options['clamav']:
            from sentinelav.detection.clamav_engine import environment_ready, read_endpoint

            self.clamav = read_endpoint()
            # Reported once per scan, never as a per-file error. Not installed at all is shown on the Updates page instead.
            if not self.clamav and environment_ready():
                self.warnings.append(
                    'ClamAV signatures unavailable: the ClamAV service is not running'
                )

    def analyze_bytes(self, data, sha=None):
        """Check a block of bytes against the signature layers: hashes, the EICAR test string, YARA
        rules, rule packs and ClamAV.

        Returns (names, matches, errors): names are decisive identity matches (for example 'YARA:
        SomeFamily'), matches are detailed rule matches (including weaker 'generic' technique rules
        that only add weight), and errors describes any layer that failed.
        """
        if self.options['signature_free']:
            return [], [], []
        sha = sha or hashlib.sha256(data).hexdigest()
        if sha in self.trusted_hashes:
            return [], [], []
        names = []
        matches = []
        errors = []
        # Hash lists include the empty file, so empty content never matches by hash.
        label = self.signatures.get(sha) if len(data) >= MIN_HASH_BYTES else None
        if label is not None:
            names.append('SHA-256: ' + label)
        if self.md5 and len(data) >= MIN_HASH_BYTES:
            listed = self.md5.get(hashlib.md5(data).hexdigest())
            if listed and label is None:
                names.append(f'MD5: listed by {listed}')
        # The standard EICAR antivirus test string, split in two so this source file itself is not
        # flagged.
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        if eicar in data:
            names.append('EICAR test file (not malware)')
        if self.rules:
            try:
                for match in self.rules.match(data=bytes(data), timeout=5):
                    found = evidence(match, self.rule_metadata)
                    # Technique rules add score weight; only family rules are decisive.
                    if found.get('scope') != 'generic':
                        names.append('YARA: ' + match.rule)
                    matches.append(found)
            except Exception as error:
                errors.append('YARA inspection failed: ' + str(error))
        for pack in self.packs:
            try:
                for item in pack.match(data):
                    if item['kind'] == 'family':
                        names.append('YARA-Forge: ' + item['rule'])
                    else:
                        matches.append(item)
            except Exception as error:
                errors.append(f'Rule pack {pack.name} inspection failed: ' + str(error)[:120])
        if self.clamav:
            self.clamav_check(data, names, matches, errors)
        return names, matches, errors

    def clamav_check(self, data, names, matches, errors):
        """Send the bytes to ClamAV and add its answer to names (a named signature) or matches (a
        heuristic hint).
        """
        from sentinelav.detection.clamav_engine import STREAM_LIMIT, scan_bytes

        if len(data) > STREAM_LIMIT:
            return
        try:
            found = scan_bytes(self.clamav, data)
        except OSError as error:
            self.clamav = None
            self.warnings.append('ClamAV stopped answering during this scan: ' + str(error)[:120])
            return
        except Exception as error:
            errors.append(str(error)[:160])
            return
        if not found:
            return
        if found.startswith('Heuristics.') or found.startswith('PUA.'):
            # ClamAV heuristics describe traits, not identities, so they add weight instead of deciding.
            matches.append(
                dict(
                    rule=found,
                    code='clamav_heuristic',
                    scope='generic',
                    layer='clamav_heuristic',
                    group='clamav_heuristic',
                    weight=40,
                    category=found.split('.')[1] if '.' in found else 'Heuristic',
                    description=f'ClamAV heuristic: {found}',
                )
            )
        else:
            names.append('ClamAV: ' + found)

    def excluded(self, path):
        """Tell whether a path is inside one of the excluded folders."""
        resolved = path.resolve()
        return any(resolved == p or p in resolved.parents for p in self.exclusions)

    def analyze_member(self, data, sha=None):
        """Like analyze_bytes, but for content extracted from inside another file.

        If the content is a Windows program and the learned models are enabled, it also runs the
        advanced pipeline on it, within a per-file budget so that an archive full of programs cannot
        make a scan take forever.
        """
        reasons, matches, errors = self.analyze_bytes(data, sha)
        if (
            self.advanced
            and data.startswith(b'MZ')
            and (self.options['model'] or self.options['neural'])
        ):
            digest = sha or hashlib.sha256(data).hexdigest()
            if digest not in self.member_seen:
                self.member_seen.add(digest)
                if (
                    len(self.member_seen) > 50
                    or len(data) > 8 * 1024 * 1024
                    or self.member_bytes + len(data) > 32 * 1024 * 1024
                ):
                    errors.append('Embedded learned-analysis budget reached')
                else:
                    self.member_bytes += len(data)
                    try:
                        from sentinelav.detection.file_formats import pe_metadata, static_analysis

                        metadata = pe_metadata(data)
                        decision = self.advanced.inspect(
                            data,
                            Path('decoded.exe'),
                            digest,
                            static_analysis(data, metadata),
                            metadata,
                            self.analyze_bytes,
                            lambda: False,
                        )
                        self.current_scan_result.setdefault('embedded_model_analysis', []).append(
                            dict(
                                parent_path=self.current_parent,
                                member_sha256=digest,
                                bytes=len(data),
                                coverage=decision['coverage'],
                                verdict=decision['verdict'],
                                omissions=decision['omissions'],
                                automatic_response_eligible=False,
                                scope='Extracted or virtual bytes; no physical-file response authority',
                            )
                        )
                        errors.extend(decision['omissions'])
                        if decision['verdict'] == 'Review':
                            self.current_scan_result['advanced_review_total'] += 1
                            if len(self.current_scan_result['advanced_reviews']) < 50:
                                self.current_scan_result['advanced_reviews'].append(
                                    dict(
                                        path=self.current_parent,
                                        sha256=self.current_parent_sha,
                                        member_sha256=digest,
                                        reasons=[
                                            'Extracted bytes: ' + item['description']
                                            for item in decision['evidence'][:16]
                                        ],
                                        omissions=decision['omissions'][:8],
                                        automatic_response_eligible=False,
                                    )
                                )
                    except Exception as error:
                        errors.append('Embedded model inspection unavailable: ' + str(error)[:200])
        return reasons, matches, errors
