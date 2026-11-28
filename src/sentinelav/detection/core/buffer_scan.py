# Purpose: Bounded byte-only inspection. Never treats a content label as a file path.
# Works with: sibling modules in detection
# Used by: detection.inspection, detection.core.inspection_worker, platform.core.amsi_broker, tests.unit.test_amsi_buffers

"""Bounded byte-only inspection. Never treats a content label as a file path."""

import hashlib

MAX_BUFFER = 1024 * 1024


def inspect_buffer(scanner, content):
    """Scan a block of bytes in memory (at most 1 MiB) and return a small verdict dictionary.

    Used for content handed to us directly, for example by the Windows AMSI interface that lets
    antivirus check scripts before they run. The content is never written to disk or treated as a
    path.
    """
    if not isinstance(content, bytes):
        raise TypeError('Buffer content must be bytes')
    if len(content) > MAX_BUFFER:
        raise ValueError('Buffer exceeds the 1 MiB inspection limit')
    digest = hashlib.sha256(content).hexdigest()
    reasons, matches, errors = scanner.analyze_bytes(content, digest)
    return dict(
        kind='buffer',
        sha256=digest,
        bytes=len(content),
        detected=bool(reasons),
        reasons=reasons,
        yara_matches=matches,
        errors=errors,
        complete=not errors,
        verdict='Detected' if reasons else 'Indeterminate' if errors else 'No match',
        scope='Exact bytes only; no execution, archive expansion, file response, or recursive AMSI call',
    )
