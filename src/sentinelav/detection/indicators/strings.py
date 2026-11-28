# Purpose: Bounded string extraction and generic behavior indicators for compiled content.
# Works with: detection.helpers.threat_score
# Used by: detection.indicators, detection.indicators.unix, detection.indicators.dos

"""Bounded string extraction and generic behavior indicators for compiled content."""

import re
from sentinelav.detection.helpers.threat_score import indicator

MAX_SCAN = 16 * 1024 * 1024
ASCII = re.compile(rb'[\x20-\x7e]{5,512}')
WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){5,512}')
PRIVATE_IP = re.compile(r'^(?:0\.|10\.|127\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)')
# (code, group, weight, category, explanation, minimum distinct matches, pattern)
RULES = (
    (
        'shadow_copy_deletion',
        'ransomware',
        40,
        'Ransomware',
        'Contains commands that delete Windows shadow copies or disable recovery, which blocks file restoration.',
        1,
        r'vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit(?:\.exe)?\s*/set\s*\{?\w*\}?\s*recoveryenabled\s+no',
    ),
    (
        'ransom_language',
        'ransomware',
        35,
        'Ransomware',
        'Contains ransom-note wording about encrypted files and payment.',
        2,
        (
            r'(?:your|all)\s+(?:\w+\s+){0,3}files\s+(?:\w+\s+){0,2}encrypted|files\s+(?:have\s+been|were|are)\s+(?:\w+\s+)?encrypted|recover\s+your\s+files|decrypt\s+your\s+files',
            r'pay(?:ment)?\s+(?:\w+\s+){0,3}(?:bitcoin|btc|ransom)|bitcoin\s+(?:address|wallet)|\bransom\b|send\s+\$?\d+|tor\s+browser|\.onion\b',
        ),
    ),
    (
        'autorun_registry',
        'persistence',
        12,
        'Persistence',
        'References a Windows autorun registry key used to start at sign-in.',
        1,
        r'software\\+microsoft\\+windows\\+currentversion\\+run(?:once|services)?\b|\\+winlogon\\+(?:shell|userinit)|image file execution options',
    ),
    (
        'encoded_powershell',
        'download',
        25,
        'Downloader',
        'Embeds a hidden or encoded PowerShell command or an in-memory download.',
        1,
        r'powershell(?:\.exe)?[^\r\n]{0,60}\s-(?:e|en|enc|enco|encodedcommand|w\s+hidden|windowstyle\s+hidden|nop\s)|downloadstring\s*\(|invoke-expression|\biex\s*\(new-object',
    ),
    (
        'security_tampering',
        'evasion',
        25,
        'Evasion',
        'Contains commands that disable security tools or the firewall.',
        1,
        r'disableantispyware|disablerealtimemonitoring|set-mppreference|netsh\s+(?:advfirewall|firewall)\s+[^\r\n]{0,40}(?:off|disable|add\s+allowedprogram)|sc\s+(?:stop|config)\s+(?:windefend|wscsvc|sharedaccess)|taskkill[^\r\n]{0,40}(?:msmpeng|avp|avast|mcafee|norton|kaspersky)',
    ),
    (
        'raw_ip_url',
        'download',
        12,
        'Downloader',
        'Contains a URL that points directly at a public IP address.',
        1,
        r'__RAW_IP__',
    ),
    (
        'hidden_service_address',
        'remote_control',
        15,
        'Backdoor',
        'References a Tor hidden-service address.',
        1,
        r'\b[a-z2-7]{16,56}\.onion\b',
    ),
    (
        'keylog_markers',
        'input_capture',
        16,
        'Keylogger',
        'Contains labels for captured special keys, as keylogger logs do.',
        3,
        r'\[(?:backspace|enter|tab|caps\s?lock|shift|ctrl|esc|del|f1|left|right|bksp)\]|<(?:backspace|enter|caps\s?lock)>',
    ),
    (
        'credential_store_paths',
        'credentials',
        20,
        'Stealer',
        'References browser password databases, cryptocurrency wallets or credential dumps.',
        2,
        r'login\s+data|wallet\.dat|signons\.sqlite|logins\.json|\\+microsoft\\+credentials|sekurlsa|lsass\.dmp|cookies\.sqlite|filezilla\\+recentservers|\\+outlook\\+.*pop3',
    ),
    (
        'irc_bot_protocol',
        'remote_control',
        18,
        'Backdoor',
        'Contains IRC client commands commonly used for botnet control.',
        3,
        (r'\bprivmsg\s+[#%]', r'\bjoin\s+[#%]', r'\bnick\s+%s', r'\bpong\s+:?%s|\bping\s+:'),
    ),
    # Mail clients and transfer libraries legitimately speak SMTP, so this only corroborates other evidence.
    (
        'mass_mail_protocol',
        'replication',
        10,
        'Worm',
        'Contains the SMTP conversation needed to send mail on its own.',
        3,
        (r'\b(?:helo|ehlo)\s', r'\bmail\s+from:', r'\brcpt\s+to:', r'\bcontent-type:\s*multipart'),
    ),
    (
        'removable_media_spread',
        'replication',
        22,
        'Worm',
        'Writes an autorun.inf, the classic way to spread by removable media.',
        2,
        r'autorun\.inf|\[autorun\]|shell\\+open\\+command|open\s*=\s*\S+\.exe|shellexecute\s*=',
    ),
    (
        'raw_disk_access',
        'destruction',
        25,
        'Bootkit',
        'Opens a raw physical disk, which allows overwriting the boot record.',
        1,
        r'\\\\+\.\\+physicaldrive\d|\\+device\\+harddisk\d|\\+\?\?\\+physicaldrive',
    ),
    (
        'anti_vm_checks',
        'evasion',
        12,
        'Evasion',
        'Checks for several virtual machine or sandbox artifacts.',
        2,
        r'vboxservice|vboxguest|vmtoolsd|vmware\s*tools|sbiedll|wine_get_unix_file_name|qemu-ga|\bvmusrvc\b|cuckoomon|ollydbg|x64dbg|procmon',
    ),
    (
        'self_delete_command',
        'evasion',
        14,
        'Dropper',
        'Contains a command line that deletes the program after it runs.',
        1,
        r'cmd(?:\.exe)?\s*/c\s+(?:ping[^\r\n&]{0,40}&\s*)?del\s|/c\s+del\s+%|:repeat\s+del\s',
    ),
    (
        'shell_spawn_download',
        'download',
        20,
        'Downloader',
        'Contains a command that downloads and starts another program.',
        1,
        r'certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+/transfer|mshta(?:\.exe)?\s+https?:|regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:http',
    ),
    (
        'ddos_vocabulary',
        'remote_control',
        18,
        'Botnet',
        'Contains flood-attack commands typical of DDoS bots.',
        2,
        r'\b(?:udp|syn|tcp|http|ack|icmp)[ _-]?flood\b|\bddos\b|\bslowloris\b|\bstopflood\b',
    ),
)
# A tuple lists separate concepts, so two wordings of one idea cannot satisfy a multi-concept rule.
_COMPILED = [
    (
        *rule[:6],
        (
            [re.compile(p, re.I) for p in rule[6]]
            if isinstance(rule[6], tuple)
            else re.compile(rule[6], re.I)
        ),
    )
    for rule in RULES
]
RAW_IP_URL = re.compile(r'https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/|\b)', re.I)


def extract(data, limit=MAX_SCAN):
    """Return lowercase text of printable ASCII and UTF-16LE runs, bounded for memory."""
    view = bytes(data[:limit])
    parts = [match.group().decode('ascii') for _, match in zip(range(200000), ASCII.finditer(view))]
    parts += [
        match.group().decode('utf-16le') for _, match in zip(range(100000), WIDE.finditer(view))
    ]
    return '\n'.join(parts).casefold()


LAUNCHER = re.compile(
    r'\b(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil)(?:\.exe)?\b',
    re.I,
)
LAUNCH_ARGUMENTS = re.compile(
    r'https?://|-enc|-w(?:indowstyle)?\s+hidden|/c\s+\S|\.(?:vbs|js|hta|ps1|bat|dll)\b', re.I
)


def shortcut_indicators(data):
    """A shortcut normally opens a program or document. One that starts an interpreter with arguments is a known lure."""
    text = extract(data, 1024 * 1024)
    launcher = LAUNCHER.search(text)
    if not launcher:
        return []
    found = [
        indicator(
            'shortcut_starts_interpreter',
            'dropper',
            30,
            'A shortcut file starts a command interpreter or script host.',
            category='Dropper',
            evidence=launcher.group(),
        )
    ]
    arguments = LAUNCH_ARGUMENTS.search(text)
    if arguments:
        found.append(
            indicator(
                'shortcut_passes_script_arguments',
                'download',
                25,
                'The shortcut passes a script, URL or hidden-window option to that interpreter.',
                category='Downloader',
                evidence=arguments.group(),
            )
        )
    return found


def indicators(data, kind='pe', text=None):
    """Check the readable strings of a compiled file against the generic behaviour rules in RULES.

    Some rules need several different matches before they count (the 'minimum' column), because one
    stray word proves little.
    """
    text = extract(data) if text is None else text
    found = []
    for code, group, weight, category, explanation, minimum, pattern in _COMPILED:
        if isinstance(pattern, list):
            matches = {hit.group().strip() for hit in (p.search(text) for p in pattern) if hit}
        elif code == 'raw_ip_url':
            matches = {
                m.group(1) for m in RAW_IP_URL.finditer(text) if not PRIVATE_IP.match(m.group(1))
            }
        else:
            matches = {m.group().strip() for _, m in zip(range(256), pattern.finditer(text))}
        if len(matches) >= minimum:
            found.append(
                indicator(
                    code,
                    group,
                    weight,
                    explanation,
                    category=category,
                    evidence=', '.join(sorted(matches))[:160],
                )
            )
    return found
