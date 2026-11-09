# Purpose: Bounded byte-only inspection. Never treats a content label as a file path.
# Works with: sibling modules in detection
# Used by: detection.inspection, detection.inspection_worker, platform.amsi_broker, tests.unit.test_amsi_buffers

"""Bounded byte-only inspection. Never treats a content label as a file path."""
import hashlib

MAX_BUFFER = 1024 * 1024


def inspect_buffer(scanner, content):
    if not isinstance(content, bytes):
        raise TypeError('Buffer content must be bytes')
    if len(content) > MAX_BUFFER:
        raise ValueError('Buffer exceeds the 1 MiB inspection limit')
    digest = hashlib.sha256(content).hexdigest()
    reasons, matches, errors = scanner.analyze_bytes(content, digest)
    return dict(kind='buffer', sha256=digest, bytes=len(content),
                detected=bool(reasons), reasons=reasons, yara_matches=matches,
                errors=errors, complete=not errors,
                verdict='Detected' if reasons else 'Indeterminate' if errors else 'No match',
                scope='Exact bytes only; no execution, archive expansion, file response, or recursive AMSI call')
