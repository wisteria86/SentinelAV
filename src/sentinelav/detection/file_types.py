# Purpose: Classify inspected bytes by content; extensions are only a tie-breaking hint.
# Works with: detection.file_analysis, detection.indicators
# Used by: detection.file_analysis, detection.archive_inspection, lab.qualification.zoo_guest

"""Classify inspected bytes by content; extensions are only a tie-breaking hint."""
import re
import struct

SCRIPT_BY_SUFFIX={'.ps1':'powershell','.psm1':'powershell','.psd1':'powershell','.vbs':'vbscript','.vbe':'vbscript',
    '.js':'javascript','.jse':'javascript','.wsf':'vbscript','.hta':'html','.bat':'batch','.cmd':'batch',
    '.sh':'shell','.bash':'shell','.py':'python','.pl':'perl','.php':'php','.rb':'ruby','.lua':'lua'}
ARCHIVE_MAGIC=((b'7z\xbc\xaf\x27\x1c','7z'),(b'Rar!\x1a\x07','rar'),(b'\x1f\x8b','gzip'),(b'BZh','bzip2'),
    (b'\xfd7zXZ\x00','xz'),(b'MSCF','cab'))
ANALYZED={'pe','dos_mz','com','elf','macho','dex','apk','jar','class','ole','ooxml','pdf','rtf','html','lnk',
    'powershell','vbscript','javascript','batch','shell','python','perl','php','ruby','lua',
    'zip','tar','gzip','bzip2','xz','7z','rar'}
# Non-executable content cannot carry static behavior, so "no analyzer" is not a coverage gap for it.
INERT={'text','empty','image','media','font','source_code','metadata'}
METADATA_MAGIC=(b'\x00\x00\x00\x01Bud1',)
MEDIA_MAGIC=(b'8BPS',b'icns',b'\x89PNG',b'\xff\xd8\xff',b'GIF8',b'BM',b'RIFF',b'ID3',b'OggS',b'fLaC',b'\x00\x00\x00\x18ftyp',b'\x00\x00\x00\x20ftyp')
SCRIPT_PATTERNS=(
    ('powershell',rb'(?i)\b(invoke-expression|invoke-webrequest|new-object\s+[\w.]+|\[system\.[\w.]+\]|\$env:\w+|set-executionpolicy|write-host)\b'),
    ('vbscript',rb'(?i)\b(createobject\s*\(|wscript\.|on\s+error\s+resume\s+next|end\s+sub\b|dim\s+\w+)'),
    ('batch',rb'(?im)^\s*(@echo\s+off|set\s+\w+=|goto\s+\w+|if\s+exist\s|copy\s+%0|del\s+/[a-z])'),
    ('javascript',rb'(?i)\b(activexobject|wscript\.shell|document\.write|function\s*\(|var\s+\w+\s*=|eval\s*\()'),
    ('php',rb'<\?php\b'),
)
SOURCE_SUFFIXES={'.c','.h','.cpp','.cc','.cs','.asm','.s','.java','.pas','.go','.rs','.mak','.sln','.vcxproj','.dsp'}


def _macho(data):
    return data[:4] in (b'\xfe\xed\xfa\xce',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xcf\xfa\xed\xfe') or (
        data[:4]==b'\xca\xfe\xba\xbe' and len(data)>8 and 0<struct.unpack('>I',data[4:8])[0]<=16)


def _zip_kind(data):
    """Inspect central-directory names without decompressing or trusting a suffix."""
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
            names={item.filename.casefold() for item in archive.infolist()[:4096]}
    except (zipfile.BadZipFile,OSError,ValueError,RuntimeError,NotImplementedError):
        return 'zip'
    if 'androidmanifest.xml' in names and any(n.endswith('.dex') for n in names):return 'apk'
    if '[content_types].xml' in names:return 'ooxml'
    if 'meta-inf/manifest.mf' in names and any(n.endswith('.class') for n in names):return 'jar'
    return 'zip'


def _looks_textual(sample):
    if not sample:return False
    if sample[:2] in (b'\xff\xfe',b'\xfe\xff'):return True
    return sum(byte in (9,10,13) or 32<=byte<127 or byte>=160 for byte in sample)/len(sample)>.93 and b'\0' not in sample


def _is_com(data,suffix):
    """A COM image has no magic; demand the extension and a plausible first instruction."""
    return suffix=='.com' and 2<=len(data)<=65280 and data[0] in (0xE9,0xEB,0xE8,0xB8,0xB4,0xBA,0xBB,0xBE,0xBF,0xFA,0xFC,0x8C,0x0E,0x1E,0x50,0x33,0x31,0x90)


def _dos_mz(data):
    if len(data)<64:return True
    offset=struct.unpack_from('<I',data,0x3c)[0]
    return not (offset+4<=len(data) and data[offset:offset+2] in (b'PE',b'NE',b'LE',b'LX'))


def classify(data,suffix=''):
    """Return dict(kind, platform, analyzed, executable); pure and bounded."""
    data=bytes(data[:64*1024*1024]) if len(data)>64*1024*1024 else data
    suffix=(suffix or '').casefold()
    kind='data';platform='Generic'
    head=bytes(data[:4096])
    if not data:kind='empty'
    elif head.startswith(b'MZ'):
        offset=struct.unpack_from('<I',data,0x3c)[0] if len(data)>=64 else 0
        if not _dos_mz(data) and data[offset:offset+2]==b'PE':kind,platform='pe','Win32'
        elif not _dos_mz(data):kind,platform='dos_mz','Win16'
        else:kind,platform='dos_mz','DOS'
    elif head.startswith(b'\x7fELF'):kind,platform='elf','Linux'
    elif _macho(head):kind,platform='macho','OSX'
    elif head[:8].startswith(b'dex\n'):kind,platform='dex','Android'
    elif head.startswith(b'\xca\xfe\xba\xbe'):kind,platform='class','Java'
    elif head.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):kind,platform='ole','Office'
    elif head.startswith(b'%PDF-') or b'%PDF-' in head[:1024]:kind,platform='pdf','PDF'
    elif head.lstrip().startswith(b'{\\rt'):kind,platform='rtf','Office'
    elif head.startswith(b'L\x00\x00\x00\x01\x14\x02\x00'):kind,platform='lnk','Win32'
    elif head.startswith((b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')):
        kind=_zip_kind(data)
        platform={'apk':'Android','jar':'Java','ooxml':'Office'}.get(kind,'Generic')
    elif len(data)>262 and bytes(data[257:262])==b'ustar':kind='tar'
    else:
        for magic,name in ARCHIVE_MAGIC:
            if head.startswith(magic):kind=name;break
        if kind=='data' and head.startswith(MEDIA_MAGIC):kind='media'
        if kind=='data' and head.startswith(METADATA_MAGIC):kind='metadata'
        if kind=='data' and suffix in ('.exe','.dll','.scr','.sys'):kind='data'
        if kind=='data' and _is_com(data,suffix):kind,platform='com','DOS'
        if kind=='data' and _looks_textual(head):
            kind=_text_kind(data,suffix)
            platform={'powershell':'PowerShell','vbscript':'VBS','javascript':'JS','batch':'BAT','shell':'Linux','php':'PHP',
                      'python':'Python','perl':'Perl','ruby':'Ruby','lua':'Lua','html':'HTML'}.get(kind,'Generic')
    return dict(kind=kind,platform=platform,analyzed=kind in ANALYZED,inert=kind in INERT,
        executable=kind in ('pe','dos_mz','com','elf','macho','dex','apk','jar','class'))


def _text_kind(data,suffix):
    head=bytes(data[:65536])
    if head[:2] in (b'\xff\xfe',b'\xfe\xff'):
        try:head=head.decode('utf-16').encode('utf-8','replace')
        except UnicodeError:pass
    if suffix in SCRIPT_BY_SUFFIX:return SCRIPT_BY_SUFFIX[suffix]
    if suffix in SOURCE_SUFFIXES:return 'source_code'
    if head.startswith(b'#!'):
        line=head.split(b'\n',1)[0].lower()
        for token,name in ((b'python','python'),(b'perl','perl'),(b'ruby','ruby'),(b'php','php'),(b'sh','shell')):
            if token in line:return name
    lowered=head[:1024].lstrip().lower()
    if lowered.startswith((b'<!doctype html',b'<html')) or suffix in ('.html','.htm','.xhtml') or b'<script' in lowered:return 'html'
    for name,pattern in SCRIPT_PATTERNS:
        if len(re.findall(pattern,head))>=(1 if name=='php' else 2):return name
    return 'text'
