# Purpose: Run Mandiant capa on undecided Windows programs and turn strong capabilities into capped evidence.
# Works with: detection.threat_score, detection.definition_paths
# Used by: detection.file_analysis

"""Run Mandiant capa on undecided Windows programs and turn strong capabilities into capped evidence.

capa (Apache-2.0) is a separate program that statically disassembles a file and
names what its code can do. It takes tens of seconds per file and many of its
rules match ordinary software (even Notepad "uses anti-debugging instructions"),
so SentinelAV runs it only on Windows programs whose score is already Suspicious
but not Malicious, and counts only capabilities that legitimate software rarely
combines: code injection, recovery sabotage, keylogging, credential theft,
sandbox evasion, persistence and remote control. Their total is capped.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from sentinelav.detection.threat_score import indicator

TIMEOUT_SECONDS = 60
OUTPUT_LIMIT = 32 * 1024 * 1024
INPUT_LIMIT = 8 * 1024 * 1024

# (namespace prefix, code, weight, category, explanation). The first matching prefix wins for each rule.
STRONG = (
    (
        'host-interaction/process/inject',
        'capa_process_injection',
        25,
        'Injector',
        'Can write and run code inside another process.',
    ),
    (
        'impact/inhibit-system-recovery',
        'capa_inhibits_recovery',
        30,
        'Ransomware',
        'Can delete shadow copies or disable system recovery.',
    ),
    (
        'impact/',
        'capa_destructive_impact',
        20,
        'Destructive',
        'Has code to wipe, encrypt or otherwise damage data.',
    ),
    ('collection/keylog', 'capa_keylogging', 20, 'Spyware', 'Can record keystrokes.'),
    ('collection/screenshot', 'capa_screen_capture', 12, 'Spyware', 'Can capture the screen.'),
    (
        'anti-analysis/anti-vm',
        'capa_sandbox_evasion',
        15,
        'Evasion',
        'Checks whether it runs in a virtual machine or sandbox.',
    ),
    (
        'anti-analysis/anti-av',
        'capa_security_evasion',
        20,
        'Evasion',
        'Looks for or interferes with security software.',
    ),
    (
        'persistence/',
        'capa_persistence',
        15,
        'Persistence',
        'Can install itself to start automatically.',
    ),
    (
        'communication/c2/',
        'capa_remote_control',
        20,
        'Backdoor',
        'Has command-and-control handling for remote instructions.',
    ),
)
# Credential theft is named by ATT&CK tactic rather than one namespace.
CREDENTIAL_TACTIC = 'Credential Access'


def locate():
    """capa.exe from SENTINELAV_CAPA, a `capa` folder beside the application, then the work drive's tool area."""
    from sentinelav.paths import PROJECT_ROOT

    if os.environ.get('SENTINELAV_CAPA'):
        path = Path(os.environ['SENTINELAV_CAPA'])
        return path if path.is_file() else None
    bundled = PROJECT_ROOT / 'capa' / 'capa.exe'
    if bundled.is_file():
        return bundled
    root = Path(os.environ.get('SENTINELAV_WORK_ROOT', 'F:/SentinelAV-Work')) / 'tools'
    if root.is_dir():
        for folder in sorted(root.glob('capa-*'), reverse=True):
            if (folder / 'capa.exe').is_file():
                return folder / 'capa.exe'
    return None


def run(path, program=None):
    """capa's JSON report for one file on disk."""
    program = program or locate()
    if program is None:
        raise FileNotFoundError('capa is not installed')
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    process = subprocess.Popen(
        [str(program), '-j', str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    try:
        output, _ = process.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # capa.exe unpacks itself into a second process that holds the output pipe, so the whole tree must end.
        _end_tree(process)
        raise TimeoutError(f'capa took longer than {TIMEOUT_SECONDS} seconds')
    if process.returncode != 0:
        raise RuntimeError(f'capa exited with code {process.returncode}')
    if len(output) > OUTPUT_LIMIT:
        raise ValueError('capa report exceeds its size limit')
    return json.loads(output)


def _end_tree(process):
    """Forcefully stop a process together with every child process it started."""
    if os.name == 'nt':
        subprocess.run(
            ['taskkill', '/T', '/F', '/PID', str(process.pid)],
            capture_output=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            timeout=30,
        )
    else:
        process.kill()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run_bytes(data, program=None):
    """Analyze in-memory content through a private temporary copy, removed afterwards (used in disposable lab guests)."""
    if len(data) > INPUT_LIMIT:
        raise ValueError('File too large for capability analysis')
    handle, name = tempfile.mkstemp(suffix='.bin', prefix='sentinelav-capa-')
    try:
        with os.fdopen(handle, 'wb') as output:
            output.write(data)
        return run(name, program)
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def capability_items(path, data, in_memory, omissions):
    """capa evidence for a file on disk, or for in-memory content when the caller allows a temporary copy."""
    if len(data) > INPUT_LIMIT:
        return []  # Large programs take capa minutes; the other layers still judge them.
    try:
        if path and Path(path).is_file():
            return indicators(run(path))
        if in_memory:
            return indicators(run_bytes(data))
    except Exception as error:
        omissions.append('Capability analysis (capa) unavailable: ' + str(error)[:160])
    return []


def indicators(report):
    """Strong capabilities in a capa report, one indicator per kind, all in the capped 'capa' group."""
    found = {}
    for name, rule in (report.get('rules') or {}).items():
        meta = rule.get('meta') or {}
        if meta.get('lib'):
            continue
        namespace = meta.get('namespace') or ''
        tactics = {entry.get('tactic') for entry in meta.get('attack') or []}
        # Use the first entry in STRONG whose namespace matches this rule; credential theft is
        # recognised by its ATT&CK tactic instead.
        chosen = next((entry for entry in STRONG if namespace.startswith(entry[0])), None)
        if chosen is None and CREDENTIAL_TACTIC in tactics:
            chosen = (
                '',
                'capa_credential_theft',
                25,
                'Stealer',
                'Can read stored passwords or other credentials.',
            )
        if chosen and chosen[1] not in found:
            _, code, weight, category, explanation = chosen
            found[code] = indicator(
                code, 'capa', weight, f'capa: {explanation} (rule "{name}")', 'capa', category, name
            )
    return list(found.values())
