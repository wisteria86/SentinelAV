# Purpose: Static Android and Java indicators read in memory from bounded archive members.
# Works with: detection.threat_score, detection.indicators.strings
# Used by: detection.indicators

"""Static Android and Java indicators read in memory from bounded archive members."""

import io
import re
import zipfile
from sentinelav.detection.indicators.strings import extract
from sentinelav.detection.threat_score import indicator

MEMBER_LIMIT = 32 * 1024 * 1024
PERMISSIONS = (
    'SEND_SMS',
    'RECEIVE_SMS',
    'READ_SMS',
    'READ_CONTACTS',
    'CALL_PHONE',
    'PROCESS_OUTGOING_CALLS',
    'RECORD_AUDIO',
    'READ_CALL_LOG',
    'BIND_DEVICE_ADMIN',
    'BIND_ACCESSIBILITY_SERVICE',
    'SYSTEM_ALERT_WINDOW',
    'RECEIVE_BOOT_COMPLETED',
    'REQUEST_INSTALL_PACKAGES',
    'WRITE_SETTINGS',
    'READ_PHONE_STATE',
    'INTERNET',
    'WRITE_EXTERNAL_STORAGE',
)
ANDROID_CODE = (
    (
        'dynamic_code_loading',
        'evasion',
        18,
        'Trojan',
        'Loads extra code at runtime.',
        ('dexclassloader', 'pathclassloader', 'inmemorydexclassloader'),
    ),
    (
        'shell_or_root_commands',
        'injection',
        20,
        'Trojan',
        'Runs shell commands or tries to gain root.',
        ('runtime;->exec', '/system/bin/su', '/system/xbin/su', 'supersu', 'getruntime'),
    ),
    (
        'sms_sending_code',
        'fraud',
        28,
        'SmsTrojan',
        'Contains code that sends SMS messages without an interface.',
        ('sendtextmessage', 'sendmultiparttextmessage'),
    ),
    (
        'sms_interception',
        'credentials',
        24,
        'SmsTrojan',
        'Intercepts or aborts incoming SMS messages.',
        ('abortbroadcast', 'android.provider.telephony.sms_received'),
    ),
    (
        'device_admin_abuse',
        'persistence',
        18,
        'Trojan',
        'Requests device-administrator control or locks the device.',
        ('devicepolicymanager', 'locknow', 'resetpassword'),
    ),
    (
        'native_exploit_names',
        'injection',
        32,
        'Exploit',
        'Names a known Android root exploit technique.',
        ('rageagainstthecage', 'exploid', 'zergrush', 'gingerbreak', 'psneuter'),
    ),
)
# Terms starting with '=' must equal a class-file constant (a class, method or field name); others are substrings of any constant.
JAVA_CODE = (
    (
        'runtime_exec',
        'injection',
        20,
        'Trojan',
        'Launches operating-system commands.',
        ('=java/lang/runtime',),
        ('=exec',),
    ),
    (
        'remote_class_loading',
        'download',
        24,
        'Downloader',
        'Loads classes from a URL at runtime.',
        ('=java/net/urlclassloader',),
        ('http://', 'https://'),
    ),
    (
        'sandbox_escape_terms',
        'exploit',
        32,
        'Exploit',
        'Manipulates the Java security manager, as sandbox exploits do.',
        ('=setsecuritymanager',),
        ('=java/security/allpermission',),
    ),
    (
        'remote_control_terms',
        'remote_control',
        24,
        'Backdoor',
        'Combines sockets with screen or key capture.',
        ('=java/net/socket',),
        ('=java/awt/robot', '=createscreencapture'),
    ),
    # Loaders that keep their real classes encrypted in a resource and define them after decrypting.
    (
        'encrypted_class_loader',
        'evasion',
        25,
        'Trojan',
        'Decrypts bundled data and defines classes from it at runtime.',
        ('=defineclass',),
        ('=javax/crypto/cipher',),
    ),
    (
        'chat_webhook_exfiltration',
        'credentials',
        25,
        'Stealer',
        'Posts data to a chat webhook or bot API, a common way stealers send loot.',
        ('/api/webhooks/', 'api.telegram.org/bot'),
        (
            'login data',
            'local state',
            'leveldb',
            'cookies',
            'wallet',
            'screenshot',
            'user.home',
            'getenv',
        ),
    ),
    # Game mods that read the signed-in player's access token and also open web connections: the shape of session stealers.
    (
        'game_session_token_access',
        'credentials',
        35,
        'Stealer',
        'Reads the game account access token and can send data over the network.',
        (
            '=net/minecraft/client/user',
            '=net/minecraft/client/util/session',
            '=net/minecraft/client/session/session',
            '=net/minecraft/util/session',
            '=net/minecraft/class_320',
            '=func_148254_d',
            '=func_111286_b',
            '=method_1674',
        ),
        (
            '=java/net/httpurlconnection',
            '=java/net/http/httpclient',
            '=javax/net/ssl/httpsurlconnection',
            '=okhttp3/okhttpclient',
            '=java/net/socket',
        ),
    ),
    (
        'native_memory_injection',
        'injection',
        35,
        'Injector',
        'Calls Windows memory and thread functions through JNA, as Java shellcode loaders do.',
        ('=com/sun/jna/native', '=com/sun/jna/pointer', '=com/sun/jna/platform/win32/kernel32'),
        (
            '=virtualalloc',
            '=virtualallocex',
            '=writeprocessmemory',
            '=createremotethread',
            '=rtlmovememory',
        ),
    ),
)
# Classes a game client or mod loader defines itself; a jar that contains them is the game or loader, not a mod.
GAME_CORE = (
    'net/minecraft/client/minecraft.class',
    'net/minecraft/client/main/main.class',
    'net/fabricmc/loader/impl/fabricloaderimpl.class',
)
STRANGE_NAME = re.compile(
    r'^(?:[il1|]{5,}|[o0]{5,}|(?:con|aux|nul|prn|com\d|lpt\d))$|[^\x21-\x7e]', re.I
)


CONSTANT_SIZES = {
    7: 2,
    8: 2,
    16: 2,
    19: 2,
    20: 2,
    15: 3,
    3: 4,
    4: 4,
    9: 4,
    10: 4,
    11: 4,
    12: 4,
    17: 4,
    18: 4,
    5: 8,
    6: 8,
}


def constants(code):
    """UTF-8 constants of one class file (names, descriptors, string literals), lowercased; empty for non-class data."""
    found = set()
    if code[:4] != b'\xca\xfe\xba\xbe' or len(code) < 10:
        return found
    count = int.from_bytes(code[8:10], 'big')
    offset = 10
    index = 1
    while index < count and offset < len(code):
        tag = code[offset]
        if tag == 1:
            size = int.from_bytes(code[offset + 1 : offset + 3], 'big')
            found.add(code[offset + 3 : offset + 3 + size].decode('utf-8', 'replace').casefold())
            offset += 3 + size
        elif tag in CONSTANT_SIZES:
            offset += 1 + CONSTANT_SIZES[tag]
            index += tag in (5, 6)  # long and double take two slots
        else:
            break
        index += 1
    return found


def _has(term, names, text):
    """Check one search term: '=name' must be an exact class-file constant, anything else just has to
    appear in the text.
    """
    return term[1:] in names if term.startswith('=') else term in text


def _members(data):
    """Bounded in-memory read of code members; nothing is extracted to disk."""
    result = []
    manifest = b''
    total = 0
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        for item in archive.infolist()[:16384]:
            name = item.filename.casefold()
            if (
                item.flag_bits & 1
                or item.file_size > MEMBER_LIMIT
                or total + item.file_size > 4 * MEMBER_LIMIT
            ):
                continue
            if name == 'androidmanifest.xml' or name == 'meta-inf/manifest.mf':
                manifest = archive.read(item)
                total += len(manifest)
            elif name.endswith(('.dex', '.class', '.class/')):
                try:
                    content = archive.read(item)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError):
                    continue
                total += len(content)
                result.append(content)
    return manifest, result


def android_indicators(data, kind):
    """Find warning signs in an Android app: suspicious permission combinations and code that sends
    SMS, runs shell commands, loads code at runtime or abuses device-admin rights.
    """
    if kind == 'apk':
        manifest, code = _members(data)
    else:
        manifest = b''
        code = [bytes(data)]
    found = []
    # The binary manifest stores names as UTF-16 string-pool entries; read both encodings without XML parsing.
    plain = extract(manifest, 4 * 1024 * 1024)
    requested = {name for name in PERMISSIONS if name.casefold() in plain}
    sms = requested & {'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS'}
    if sms and 'RECEIVE_BOOT_COMPLETED' in requested:
        found.append(
            indicator(
                'sms_with_boot_start',
                'fraud',
                26,
                'Requests SMS access and starts at boot, an unusual pairing for ordinary apps.',
                category='SmsTrojan',
                evidence=', '.join(sorted(requested))[:160],
            )
        )
    elif sms:
        found.append(
            indicator(
                'sms_permissions', 'fraud', 14, 'Requests SMS permissions.', category='SmsTrojan'
            )
        )
    surveillance = requested & {
        'RECORD_AUDIO',
        'READ_CALL_LOG',
        'READ_CONTACTS',
        'PROCESS_OUTGOING_CALLS',
        'CALL_PHONE',
    }
    if len(surveillance) >= 3:
        found.append(
            indicator(
                'surveillance_permissions',
                'credentials',
                22,
                'Requests several permissions that together allow surveillance of calls and contacts.',
                category='Spyware',
                evidence=', '.join(sorted(surveillance)),
            )
        )
    if (
        requested & {'BIND_DEVICE_ADMIN', 'BIND_ACCESSIBILITY_SERVICE'}
        and 'SYSTEM_ALERT_WINDOW' in requested
    ):
        found.append(
            indicator(
                'overlay_with_admin',
                'persistence',
                28,
                'Combines screen overlays with device-admin or accessibility control, as banking trojans do.',
                category='Banker',
            )
        )
    text = '\n'.join(extract(item, 8 * 1024 * 1024) for item in code[:16])
    for code_name, group, weight, category, explanation, terms in ANDROID_CODE:
        hits = [term for term in terms if term in text]
        if hits:
            found.append(
                indicator(
                    code_name,
                    group,
                    weight,
                    explanation,
                    category=category,
                    evidence=', '.join(hits)[:160],
                )
            )
    return found


def java_indicators(data, kind):
    """Find warning signs in Java code (a .jar or a single .class): obfuscated or encrypted classes and
    dangerous API combinations such as running commands, loading remote classes or stealing session
    tokens.
    """
    if kind == 'jar':
        _, code = _members(data)
    else:
        code = [bytes(data)]
    names = set().union(*(constants(item) for item in code))
    text = '\n'.join(sorted(names))
    found = []
    core = False
    jna = False
    if kind == 'jar':
        with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
            paths = [n for n in archive.namelist()[:16384] if n.endswith(('.class', '.class/'))]
        core = any(p.casefold() in GAME_CORE for p in paths)
        jna = any(p.startswith('com/sun/jna/') for p in paths)  # JNA itself, not a program using it
        classes = [n.rstrip('/').rsplit('/', 1)[-1][:-6] for n in paths]
        # Obfuscators rename classes to one or two letters, to look-alike I/l/1 strings, to Windows device names or to non-ASCII.
        short = sum(len(name) <= 2 or bool(STRANGE_NAME.search(name)) for name in classes)
        if len(classes) >= 10 and short >= 0.6 * len(classes):
            found.append(
                indicator(
                    'obfuscated_class_names',
                    'evasion',
                    15,
                    'Most classes have one- or two-letter or look-alike names, as obfuscators produce.',
                    category='Trojan',
                    evidence=f'{short} of {len(classes)} classes',
                )
            )
        strange = sum(bool(STRANGE_NAME.search(name)) for name in classes)
        if strange >= 5 and strange >= 0.3 * len(classes):
            found.append(
                indicator(
                    'hostile_class_names',
                    'evasion',
                    25,
                    'Many class names use look-alike characters, non-ASCII text or Windows device names to break analysis tools.',
                    category='Trojan',
                    evidence=f'{strange} of {len(classes)} classes',
                )
            )
        # A real class file starts with CAFEBABE; class entries that do not are encrypted and decrypted by a loader at run time.
        hidden = sum(
            item[:4] != b'\xca\xfe\xba\xbe' and not item.startswith(b'dex') for item in code
        )
        if hidden >= 3 and hidden >= 0.2 * max(1, len(code)):
            found.append(
                indicator(
                    'encrypted_class_files',
                    'evasion',
                    38,
                    'Class entries are encrypted, so a loader must decrypt and define them at run time.',
                    category='Trojan',
                    evidence=f'{hidden} of {len(code)} class entries',
                )
            )
        # The archive is compressed, so the generic string rules read the class files' constants instead.
        from sentinelav.detection.indicators.strings import indicators as string_indicators

        found.extend(string_indicators(b'\n'.join(code)[: 16 * 1024 * 1024], 'class'))
    for code_name, group, weight, category, explanation, first, second in JAVA_CODE:
        if (
            code_name == 'game_session_token_access'
            and core
            or code_name == 'native_memory_injection'
            and jna
        ):
            continue
        hit = [t.lstrip('=') for t in first if _has(t, names, text)]
        other = [t.lstrip('=') for t in second if _has(t, names, text)]
        if hit and other:
            found.append(
                indicator(
                    code_name,
                    group,
                    weight,
                    explanation,
                    category=category,
                    evidence=', '.join(hit + other)[:160],
                )
            )
    return found
