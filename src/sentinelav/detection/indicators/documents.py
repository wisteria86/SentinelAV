# Purpose: Static indicators for macros, PDF actions and RTF objects; nothing is opened or rendered.
# Works with: detection.helpers.documents, detection.helpers.threat_score, detection.indicators.scripts
# Used by: detection.indicators

"""Static indicators for macros, PDF actions and RTF objects; nothing is opened or rendered."""

import re
from sentinelav.detection.helpers.documents import macro_sources
from sentinelav.detection.helpers.threat_score import indicator

AUTO_EXEC = re.compile(
    r'\b(auto_?open|auto_?close|auto_?exec|auto_?new|auto_?exit|document_(?:open|close|new)|workbook_(?:open|beforeclose)|filesave|fileopen|filesaveas|toolsmacro|viewvbcode)\b',
    re.I,
)
SHELL = re.compile(
    r'\b(shell\s*\(|wscript\.shell|shell\.application|createobject\s*\(|urldownloadtofile|msxml2\.|winhttp\.|adodb\.stream|powershell|cmd(?:\.exe)?\s*/c|callbyname|getobject\s*\(\s*["\']winmgmts)',
    re.I,
)
REPLICATE = re.compile(
    r'\b(vbproject|vbcomponents|codemodule|\.insertlines|\.addfromstring|\.addfromfile|normaltemplate|activedocument\.vbproject|macrocontainer|organizercopy|macrocopy|application\.macrocopy|vbe\.)',
    re.I,
)
SECURITY = re.compile(
    r'\b(enablecancelkey|displayalerts\s*=\s*false|screenupdating\s*=\s*false|virusprotection|accessvbom|\\+security\\+(?:level|accessvbom)|options\.(?:virusprotection|saveNormalPrompt))',
    re.I,
)
OBFUSCATION = re.compile(
    r'(?:chrw?\$?\s*\(\s*\d+\s*\)\s*&?\s*_?\s*){8}|strreverse\s*\(|(?:["\'][^"\']{1,4}["\']\s*&\s*_?\s*){8}',
    re.I,
)
# Ordinary documents name their template in metadata, so only an explicit copy command counts as replication.
LEGACY_MACRO = re.compile(
    rb'(?i)(?:autoopen|autoclose|autoexec|autonew|fileopen|filesaveas|toolsmacro)|m\x00a\x00c\x00r\x00o\x00c\x00o\x00p\x00y|macrocopy|organizercopy'
)
EXPLOIT_CLSID = (
    b'0002ce02-0000-0000-c000-000000000046',
    b'00021700-0000-0000-c000-000000000046',
    b'equation.3',
    b'equation.2',
    b'htmlfile',
    b'scriptlet',
    b'package\x00',
)


def _macro(source, name):
    """Check one macro's source code for risky behaviour: auto-run triggers, launching programs, self-
    copying, disabling security prompts and obfuscation.
    """
    text = (
        source.decode('utf-8', errors='replace')
        if isinstance(source, (bytes, bytearray))
        else source
    )
    found = []
    auto = AUTO_EXEC.search(text)
    if auto:
        found.append(
            indicator(
                'macro_auto_exec',
                'macro_trigger',
                18,
                'A macro runs automatically when the document is opened or saved.',
                category='Macro',
                evidence=auto.group(),
            )
        )
    shell = SHELL.search(text)
    if shell:
        found.append(
            indicator(
                'macro_launches_or_downloads',
                'macro_action',
                32,
                'A macro can launch programs or download content.',
                category='Macro',
                evidence=shell.group(),
            )
        )
    copy = REPLICATE.search(text)
    if copy:
        found.append(
            indicator(
                'macro_self_replication',
                'replication',
                42,
                'A macro copies code into other documents or the global template, which is how macro viruses spread.',
                category='MacroVirus',
                evidence=copy.group(),
            )
        )
    tamper = SECURITY.search(text)
    if tamper:
        found.append(
            indicator(
                'macro_hides_activity',
                'obfuscation',
                14,
                'A macro disables prompts or macro-security settings.',
                category='Macro',
                evidence=tamper.group(),
            )
        )
    if OBFUSCATION.search(text):
        found.append(
            indicator(
                'macro_obfuscation',
                'obfuscation',
                16,
                'Macro text is assembled from many fragments or character codes.',
                category='Macro',
            )
        )
    return found


def office_indicators(data, omissions=None):
    """Find warning signs in an Office document: risky macros, legacy macro-virus commands, embedded
    programs and OLE objects that exploits like to use.
    """
    omissions = [] if omissions is None else omissions
    sources, errors = macro_sources(data)
    omissions.extend(errors)
    found = {}
    for name, source in sources:
        for item in _macro(source, name):
            found.setdefault(item['code'], item)
    raw = bytes(data[: 16 * 1024 * 1024])
    # Word 6/95 macros are not always decompressible as VBA, so keep a raw-bytes view of their trigger names.
    if (
        not sources
        and LEGACY_MACRO.search(raw)
        and raw.startswith(bytes.fromhex('d0cf11e0a1b11ae1'))
    ):
        names = sorted(
            {
                m.group().decode('latin-1').replace('\0', '').casefold()
                for _, m in zip(range(32), LEGACY_MACRO.finditer(raw))
            }
        )
        found['legacy_macro_triggers'] = indicator(
            'legacy_macro_triggers',
            'macro_trigger',
            28,
            'A legacy document holds auto-run or file-command macro names that old macro viruses replace.',
            category='MacroVirus',
            evidence=', '.join(names)[:160],
        )
        if {'macrocopy', 'organizercopy'} & set(names):
            found['legacy_macro_copy'] = indicator(
                'legacy_macro_copy',
                'replication',
                42,
                'A legacy document contains a command that copies macros between documents.',
                category='MacroVirus',
            )
    lowered = raw.lower()
    if lowered.find(b'mz') >= 0 and re.search(rb'this program (?:cannot|must) be run', lowered):
        found['embedded_program_in_document'] = indicator(
            'embedded_program_in_document',
            'dropper',
            38,
            'A Windows program is embedded inside the document.',
            category='Dropper',
        )
    hits = [item.decode('latin-1').rstrip('\0') for item in EXPLOIT_CLSID[:4] if item in lowered]
    if hits:
        found['exploitable_ole_object'] = indicator(
            'exploitable_ole_object',
            'exploit',
            38,
            'The document embeds an OLE object often abused by document exploits.',
            category='Exploit',
            evidence=', '.join(hits),
        )
    return list(found.values())


STREAM = re.compile(rb'stream\r?\n.*?(?:endstream|\Z)', re.S)
OBJECT_STREAM = re.compile(
    rb'<<((?:(?!>>).){0,2048}?/ObjStm(?:(?!>>).){0,2048}?)>>\s*stream\r?\n(.*?)endstream', re.S
)
ESCAPED_NAME = re.compile(rb'/[^\s/<>\[\]()]*#[0-9a-fA-F]{2}[^\s/<>\[\]()]*')
RISKY_NAMES = {
    b'/javascript',
    b'/js',
    b'/openaction',
    b'/aa',
    b'/launch',
    b'/embeddedfile',
    b'/richmedia',
    b'/xfa',
}


def _unescape(name):
    """Turn PDF hex escapes such as #61 back into the characters they stand for."""
    return re.sub(rb'#([0-9a-fA-F]{2})', lambda m: bytes([int(m[1], 16)]), name)


def pdf_structure(raw):
    """PDF objects outside compressed streams, plus bounded object streams, where modern files keep dictionaries.

    Compressed bytes are excluded because random data can contain sequences like /JS or #41 by chance.
    """
    import zlib

    parts = [STREAM.sub(b' ', raw)]
    expanded = 0
    for _, match in zip(range(256), OBJECT_STREAM.finditer(raw)):
        if b'/FlateDecode' not in match[1]:
            continue
        try:
            payload = zlib.decompressobj().decompress(match[2].rstrip(b'\r\n'), 4 * 1024 * 1024)
        except zlib.error:
            continue
        expanded += len(payload)
        parts.append(payload)
        if expanded > 16 * 1024 * 1024:
            break
    return b'\n'.join(parts)


def pdf_indicators(data):
    """Find warning signs in a PDF: JavaScript (especially if it runs on open), launch actions,
    embedded executables and disguised keywords.
    """
    raw = bytes(data[: 32 * 1024 * 1024])
    structure = pdf_structure(raw)
    # Name tokens may hide characters with hex escapes such as /J#61vaScript.
    disguised = [
        name
        for _, name in zip(range(4096), ESCAPED_NAME.findall(structure))
        if _unescape(name).lower() in RISKY_NAMES
    ]
    text = ESCAPED_NAME.sub(lambda m: _unescape(m.group()), structure)
    found = []
    auto = re.search(rb'/(?:OpenAction|AA)\b', text)
    script = re.search(rb'/(?:JavaScript|JS)\b', text)
    if script and auto:
        found.append(
            indicator(
                'pdf_auto_javascript',
                'exploit',
                38,
                'The PDF runs JavaScript automatically when opened.',
                category='Exploit',
            )
        )
    elif script:
        found.append(
            indicator(
                'pdf_javascript', 'exploit', 12, 'The PDF contains JavaScript.', category='Exploit'
            )
        )
    if re.search(rb'/Launch\b', text):
        found.append(
            indicator(
                'pdf_launch_action',
                'dropper',
                38,
                'The PDF can launch an external program.',
                category='Dropper',
            )
        )
    if re.search(rb'/EmbeddedFile\b', text) and re.search(
        rb'\.(?:exe|scr|js|vbs|bat|cmd|hta)\b', text, re.I
    ):
        found.append(
            indicator(
                'pdf_embedded_executable',
                'dropper',
                32,
                'The PDF embeds a file with an executable or script name.',
                category='Dropper',
            )
        )
    if re.search(rb'/(?:JBIG2Decode|XFA|RichMedia|U3D)\b', text) and script:
        found.append(
            indicator(
                'pdf_exploit_surface',
                'obfuscation',
                14,
                'JavaScript is combined with PDF features that are frequent exploit targets.',
                category='Exploit',
            )
        )
    if disguised:
        found.append(
            indicator(
                'pdf_name_obfuscation',
                'obfuscation',
                18,
                'PDF keywords are disguised using hex escapes.',
                category='Exploit',
                evidence=disguised[0].decode('latin-1'),
            )
        )
    return found


def rtf_indicators(data):
    """Find warning signs in an RTF document: auto-updating objects, Equation Editor exploits, embedded
    programs and remote templates.
    """
    raw = bytes(data[: 32 * 1024 * 1024])
    lowered = raw.lower()
    found = []
    if b'\\objupdate' in lowered and b'\\object' in lowered:
        found.append(
            indicator(
                'rtf_object_auto_update',
                'exploit',
                24,
                'The RTF forces an embedded object to load without user action.',
                category='Exploit',
            )
        )
    compact = re.sub(rb'\s', b'', lowered)
    if any(
        token in compact
        for token in (
            b'0002ce0200000000c000000000000046',
            b'equation.3',
            b'65717561746f6e2e33',
            b'equation.2',
            b'65717561746f6e2e32',
        )
    ):
        found.append(
            indicator(
                'rtf_equation_object',
                'exploit',
                40,
                'The RTF embeds an Equation Editor object, a long-exploited component.',
                category='Exploit',
            )
        )
    if len(re.findall(rb'\\objdata', lowered)) >= 1 and re.search(rb'4d5a[0-9a-f]{100,}', compact):
        found.append(
            indicator(
                'rtf_embedded_program',
                'dropper',
                42,
                'The RTF carries a hex-encoded Windows program.',
                category='Dropper',
            )
        )
    remote = re.search(
        rb'\\\*\\template\s*(?:\{[^}]{0,64}\})?\s*(https?://|\\\\\\\\|file://)', lowered
    )
    if remote:
        found.append(
            indicator(
                'rtf_remote_template',
                'download',
                40,
                'The RTF loads its template from the Internet or a network share, a way to fetch exploit content when opened.',
                category='Downloader',
                evidence=remote.group()[:80],
            )
        )
    found.extend(_rtf_objects(lowered, {item['code'] for item in found}))
    return found


TOKEN = re.compile(rb'\{|\}|\\[a-z]{1,32}-?\d{0,10} ?|\\.|[^{}\\]{1,65536}', re.S)
OBJECT_CLASSES = (
    b'equation.3',
    b'equation.2',
    b'package',
    b'ole2link',
    b'htmlfile',
    b'scriptlet',
    b'word.document.8',
    b'excel.sheet.8',
    b'forms.',
)


def _rtf_objects(lowered, already):
    """Decode \\objdata hex after removing the control words, braces and junk that exploit kits put inside it."""
    found = []
    decoded = b''
    for _, match in zip(range(16), re.finditer(rb'\\objdata', lowered)):
        # Keep only text at the top level of the \objdata group; nested groups and control words are padding.
        depth = 1
        parts = []
        for token in TOKEN.finditer(lowered, match.end(), match.end() + 8 * 1024 * 1024):
            value = token.group()
            if value == b'{':
                depth += 1
            elif value == b'}':
                depth -= 1
                if depth == 0:
                    break
            elif depth == 1 and value[:1] != b'\\':
                parts.append(value)
        digits = re.sub(rb'[^0-9a-f]', b'', b''.join(parts))
        decoded += bytes.fromhex(digits[: len(digits) // 2 * 2].decode('ascii'))[: 4 * 1024 * 1024]
    if not decoded:
        return found
    view = decoded.lower()
    if b'\xd0\xcf\x11\xe0' in view or b'equation' in view or b'ole2link' in view:
        names = [name for name in OBJECT_CLASSES if name in view]
        clsid = bytes.fromhex(
            '0003000000000000c000000000000046'
        )  # StdOleLink: loads content from a URL moniker
        url = re.search(rb'h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00|https?://', decoded)
        if (
            b'equation' in view or bytes.fromhex('02ce020000000000c000000000000046') in view
        ) and 'rtf_equation_object' not in already:
            found.append(
                indicator(
                    'rtf_equation_object',
                    'exploit',
                    40,
                    'The RTF embeds an Equation Editor object, a long-exploited component.',
                    category='Exploit',
                    evidence='decoded object data',
                )
            )
        if (clsid in decoded or b'ole2link' in view) and url:
            found.append(
                indicator(
                    'rtf_url_moniker_object',
                    'exploit',
                    40,
                    'An embedded object loads content from a URL when the document opens, as CVE-2017-0199 exploits do.',
                    category='Exploit',
                )
            )
        if b'package' in names and re.search(
            rb'\.(?:exe|scr|js|jse|vbs|vbe|hta|bat|cmd|ps1|lnk|wsf|cpl)\x00', view
        ):
            found.append(
                indicator(
                    'rtf_packaged_script_or_program',
                    'dropper',
                    38,
                    'An embedded package object carries a program or script file.',
                    category='Dropper',
                )
            )
        if (
            re.search(rb'this program (?:cannot|must) be run', view)
            and 'rtf_embedded_program' not in already
        ):
            found.append(
                indicator(
                    'rtf_embedded_program',
                    'dropper',
                    42,
                    'The RTF carries an encoded Windows program.',
                    category='Dropper',
                )
            )
    return found
