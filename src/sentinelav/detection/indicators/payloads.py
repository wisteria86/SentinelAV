# Purpose: Indicators for raw payload files with no known format: shellcode, encoded programs and compiled Python.
# Works with: detection.helpers.threat_score, detection.indicators.strings, detection.indicators.scripts
# Used by: detection.indicators

"""Indicators for raw payload files with no known format: shellcode, encoded programs and compiled Python.

Loaders keep their next stage as a bare file: position-independent shellcode
(Donut, Cobalt Strike and Metasploit stagers), a Windows program XOR-encoded
with a one-byte key or stored backwards, or a compiled Python module. These
checks read bytes only; nothing is decoded into a runnable file or executed.
"""

import re
from sentinelav.detection.helpers.threat_score import indicator

WINDOW = 1024 * 1024
DOS_TEXT = b'This program cannot be run in DOS mode'
# Thread and process environment block access: how shellcode finds loaded modules without an import table.
PEB = re.compile(
    rb'\x64\xa1\x30\x00\x00\x00|\x64\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]\x30\x00\x00\x00|\x65\x48\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00|\x65[\x4c\x48]\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00|\x65\x48\xa1\x60\x00{7}',
    re.S,
)
# ROR-13 API name hashing and get-program-counter tricks.
HASHING = re.compile(rb'\xc1[\xc8-\xcf]\x0d|\x41\xc1[\xc8-\xcf]\x0d', re.S)
GETPC = re.compile(
    rb'\xe8\x00\x00\x00\x00[\x58-\x5f]|\xd9\xee\xd9\x74\x24\xf4|\xd9\xeb\x9b\xd9\x74\x24\xf4', re.S
)
STAGER_START = (b'\xfc\xe8', b'\xfc\x48\x83\xe4\xf0\xe8', b'\xfc\x48\x81\xe4')


def shellcode(data):
    # Shellcode is small and finds its functions early; memory dumps and disk images also hold such code, but deep inside.
    """Recognise bare machine code ('shellcode') that finds Windows functions by itself, the way
    loaders and exploit payloads do.
    """
    if len(data) > 16 * 1024 * 1024:
        return []
    head = bytes(data[:WINDOW])
    peb = PEB.search(head, 0, 256 * 1024)
    hashing = peb and HASHING.search(head, max(0, peb.start() - 4096), peb.end() + 4096)
    getpc = GETPC.search(head[:4096])
    starts = head.startswith(STAGER_START)
    found = []
    if peb and (hashing or getpc or starts):
        found.append(
            indicator(
                'raw_shellcode',
                'injection',
                45,
                'The file is bare machine code that locates Windows functions by itself, as shellcode loaders do.',
                category='Injector',
                evidence=', '.join(
                    name
                    for name, hit in (
                        ('PEB access', peb),
                        ('API hashing', hashing),
                        ('get-PC', getpc),
                        ('stager start', starts),
                    )
                    if hit
                ),
            )
        )
    elif starts and hashing:
        found.append(
            indicator(
                'raw_shellcode',
                'injection',
                40,
                'The file starts like a known shellcode stager and hashes API names.',
                category='Injector',
            )
        )
    return found


def encoded_program(data):
    """A Windows program hidden by a one-byte XOR key or storing it back to front; the DOS-mode text gives it away."""
    head = bytes(data[:WINDOW])
    tail = bytes(data[-WINDOW:])[::-1]
    if DOS_TEXT in head:
        return []  # A plain program is classified as one elsewhere
    if DOS_TEXT in tail:
        return [
            indicator(
                'backwards_program',
                'dropper',
                45,
                'The file holds a Windows program stored back to front, which only a loader would undo.',
                category='Dropper',
            )
        ]
    # Try every possible one-byte XOR key on the well-known DOS stub text; if one matches, a program
    # is hidden inside.
    for key in range(1, 256):
        probe = bytes(b ^ key for b in DOS_TEXT)
        if probe in head:
            return [
                indicator(
                    'xor_encoded_program',
                    'dropper',
                    45,
                    'The file holds a Windows program hidden with a one-byte XOR key.',
                    category='Dropper',
                    evidence=f'key 0x{key:02x}',
                )
            ]
    return []


def data_indicators(data):
    """Run every raw-payload check on a file of unknown format."""
    return shellcode(data) + encoded_program(data)


def compiled_python(data):
    """Names and constants of a compiled Python module, as text the Python script rules can read."""
    # Names such as exec and eval are shorter than the generic string extractor's minimum.
    return '\n'.join(
        m.group().decode('ascii')
        for _, m in zip(
            range(200000), re.finditer(rb'[\x20-\x7e]{3,512}', bytes(data[: 8 * 1024 * 1024]))
        )
    ).casefold()


# Compiled code keeps names and constants but not syntax, so these match on which names occur together.
PYC_RULES = (
    (
        'python_exec_decoded',
        'loader',
        40,
        'Dropper',
        'Compiled Python that decodes, decompresses or unmarshals data and runs it.',
        (
            r'\b(?:exec|eval)\b',
            r'\b(?:b64decode|decompress|unhexlify|fromhex|loads)\b',
            r'\b(?:base64|zlib|lzma|bz2|marshal|binascii|codecs)\b',
        ),
    ),
    (
        'python_shellcode_runner',
        'injection',
        45,
        'Injector',
        'Compiled Python that allocates executable memory and starts machine code.',
        (
            r'\bctypes\b',
            r'\bvirtualalloc(?:ex)?\b',
            r'\b(?:createthread|createremotethread|rtlmovememory|writeprocessmemory)\b',
        ),
    ),
    (
        'chat_webhook_exfiltration',
        'credentials',
        45,
        'Stealer',
        'Compiled Python that sends browser or wallet data to a chat webhook or bot.',
        (
            r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot',
            r'login data|local state|cookies|leveldb|cryptunprotectdata|wallet',
        ),
    ),
    (
        'browser_secret_decryption',
        'credentials',
        30,
        'Stealer',
        'Compiled Python that decrypts browser-saved secrets.',
        (r'\bcryptunprotectdata\b|\bwin32crypt\b', r'login data|local state|encrypted_key'),
    ),
)


def pyc_indicators(data):
    """Find loader and stealer patterns in a compiled Python (.pyc) file by looking at which names
    occur together.
    """
    text = compiled_python(data)
    found = []
    for code, group, weight, category, explanation, patterns in PYC_RULES:
        # Large modules (documentation, lexers, analysis tools) name everything; a loader stub is small.
        if code == 'python_exec_decoded' and len(data) > 64 * 1024:
            continue
        if all(re.search(pattern, text) for pattern in patterns):
            found.append(indicator(code, group, weight, explanation, category=category))
    return found
