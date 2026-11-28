# Purpose: Fail if theZoo identifiers appear in detection logic, so results cannot be hardcoded.
# Works with: resources/zoo-tree.json, src/sentinelav/detection, resources/rules
# Used by: test.ps1, tests.unit.test_no_zoo_hardcoding

"""Fail if theZoo identifiers appear in detection logic, so results cannot be hardcoded.

Git blob IDs and published checksums would be exact-match shortcuts. Sample directory
names are checked as whole tokens. Catalogued third-party family rules are public
detections, are reported as their own evaluation arm, and are listed rather than failed.
"""

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('src/sentinelav/detection', 'src/sentinelav/platform/core/engine_policy.py')
# Everyday words that also occur inside a sample's folder name. Anything else from the inventory fails the check.
ORDINARY_WORDS = {
    'format',
    'dropper',
    'unknown',
    'ransom',
    'original',
    'stealer',
    'keylogger',
    'minimal',
    'variant',
    'supply',
    'concept',
    'realtek',
}
GENERIC_WORDS = re.compile(
    r'^(?:win32|win64|trojan|ransomware|virus|worm|linux|android|osx|bat|vbs|js|w32|wm|w97m|winx|all|msil|backdoor|rootkit|exploit)$',
    re.I,
)


def inventory(tree):
    blobs = set()
    samples = set()
    for entry in tree['entries']:
        if entry.get('oid'):
            blobs.add(entry['oid'].casefold())
        parts = entry['path'].split('/')
        if len(parts) >= 3 and parts[0] == 'malware':
            name = parts[2]
            # Keep distinctive names such as Family.Variant; bare platform words appear in ordinary code.
            samples.update(
                piece
                for piece in re.split(r'[.\s_-]+', name)
                if len(piece) >= 6 and not GENERIC_WORDS.match(piece)
            )
            samples.add(name)
    return blobs, {sample for sample in samples if sample.casefold() not in ORDINARY_WORDS}


def scan_text(text, blobs, pattern):
    """Return each Zoo identifier found in text."""
    found = [
        f'Zoo blob identity {token}'
        for token in re.findall(r'\b[0-9a-fA-F]{40}\b', text)
        if token.casefold() in blobs
    ]
    return found + [f'Zoo sample name {match.group()!r}' for match in pattern.finditer(text)]


def sample_pattern(samples):
    return re.compile(
        r'(?<![A-Za-z0-9])(?:'
        + '|'.join(sorted(map(re.escape, samples), key=len, reverse=True))
        + r')(?![A-Za-z0-9])',
        re.I,
    )


def files():
    for source in SOURCES:
        path = ROOT / source
        yield from ([path] if path.is_file() else (item for item in path.rglob('*.py')))
    yield ROOT / 'resources/rules/generic_techniques.yar'


def findings():
    blobs, samples = inventory(
        json.loads((ROOT / 'resources/zoo-tree.json').read_text(encoding='utf-8'))
    )
    pattern = sample_pattern(samples)
    problems = []
    for path in files():
        problems.extend(
            f'{path.relative_to(ROOT)}: {item}'
            for item in scan_text(path.read_text(encoding='utf-8'), blobs, pattern)
        )
    return problems


def main():
    problems = findings()
    for problem in problems:
        print(problem)
    print(f'Zoo hardcoding check: {len(problems)} problem(s)')
    return int(bool(problems))


if __name__ == '__main__':
    sys.exit(main())
