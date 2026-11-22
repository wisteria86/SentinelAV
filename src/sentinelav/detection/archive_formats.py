# Purpose: Member readers for archive formats. Members stay in memory, except cabinets, which 7-Zip reads from a short-lived temp copy. Nothing is run.
# Works with: detection.archive_inspection
# Used by: detection.archive_inspection

"""Member readers for archive formats. Members stay in memory, except cabinets, which 7-Zip reads from a short-lived temp copy. Nothing is run."""
import bz2
import io
from pathlib import Path
import lzma
import shutil
import tarfile
import zipfile
import zlib

from sentinelav.detection.archive_tool import CAB_LIMIT,cab_members,seven_zip_tool,tool_members  # noqa: F401 (re-exported)

SHARING_PASSWORDS=(b'infected',b'malware',b'virus')
EXECUTABLE_SUFFIXES=('.exe','.dll','.scr','.com','.pif','.bat','.cmd','.js','.jse','.vbs','.vbe','.ps1','.hta','.jar','.msi','.lnk','.cpl','.sys','.apk','.bin')


class Member:
    """One archive entry; read(limit) returns at most limit+1 bytes so callers can detect excess."""
    def __init__(self,name,size,read,compressed=None,encrypted=False,unsafe=False):
        self.name,self.size,self.read=name,size,read
        self.compressed,self.encrypted,self.unsafe=compressed,encrypted,unsafe


def _zip_read(archive,info):
    def read(limit):
        passwords=(None,) if not info.flag_bits&1 else SHARING_PASSWORDS
        last=None
        for password in passwords:
            try:
                with archive.open(info,pwd=password) as stream:return stream.read(limit+1)
            except RuntimeError as error:last=error  # Wrong password
            except zipfile.BadZipFile as error:last=error
        raise last or RuntimeError('Encrypted member could not be opened')
    return read


def open_zip(data):
    """Prefer the reader that also understands WinZip AES, which the standard library cannot open."""
    try:import pyzipper
    except ImportError:return zipfile.ZipFile(io.BytesIO(data))
    return pyzipper.AESZipFile(io.BytesIO(data))


# Stored, Deflate, BZIP2, LZMA, and AES (99, opened by pyzipper); other methods (Deflate64, Implode, Reduce) go to 7-Zip.
ZIP_METHODS={0,8,12,14,99}


def zip_members(data):
    archive=open_zip(data)
    if any(info.compress_type not in ZIP_METHODS for info in archive.infolist()):
        yield from tool_members(data,'.zip');return
    for info in archive.infolist():
        if info.is_dir():continue
        mode=(info.external_attr>>16)&0xffff
        yield Member(info.filename,info.file_size,_zip_read(archive,info),info.compress_size,bool(info.flag_bits&1),(mode&0o170000)==0o120000)


def tar_members(data):
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for member in archive:
            if member.isdir():continue
            if not member.isfile():
                yield Member(member.name,0,lambda limit:b'',unsafe=True);continue
            def read(limit,item=member):
                with archive.extractfile(item) as stream:return stream.read(limit+1)
            yield Member(member.name,member.size,read)


def _stream(decompressor,name):
    def members(data):
        def read(limit):
            engine=decompressor()
            # The output cap inside the decompressor stops decompression bombs before memory is used.
            return engine.decompress(data,limit+1)
        yield Member(name,-1,read,len(data))
    return members


def _gzip_engine():
    class Engine:
        def __init__(self):self.engine=zlib.decompressobj(16+zlib.MAX_WBITS)
        def decompress(self,data,limit):return self.engine.decompress(data,limit)
    return Engine()


def _bz2_engine():
    class Engine:
        def __init__(self):self.engine=bz2.BZ2Decompressor()
        def decompress(self,data,limit):return self.engine.decompress(data,max_length=limit)
    return Engine()


def _xz_engine():
    class Engine:
        def __init__(self):self.engine=lzma.LZMADecompressor()
        def decompress(self,data,limit):return self.engine.decompress(data,max_length=limit)
    return Engine()


def seven_zip_members(data):
    try:import py7zr
    except ImportError:raise RuntimeError('7z support unavailable: install py7zr') from None
    from py7zr.io import BytesIOFactory
    last=None
    for password in (None,*[item.decode() for item in SHARING_PASSWORDS]):
        try:
            with py7zr.SevenZipFile(io.BytesIO(data),password=password) as archive:
                infos=[item for item in archive.list() if not item.is_directory]
            def read_all(limit,password=password,cache={}):
                # py7zr decodes solid blocks together; extract only to memory with a total cap per file.
                factory=BytesIOFactory(limit+1)
                with py7zr.SevenZipFile(io.BytesIO(data),password=password) as archive:archive.extractall(factory=factory)
                return {name:stream for name,stream in factory.products.items()}
            shared={}
            def member_read(name):
                def read(limit):
                    if not shared:shared.update(read_all(limit))
                    stream=shared.get(name)
                    if stream is None:raise RuntimeError('7z member unavailable')
                    stream.seek(0);return stream.read(limit+1)
                return read
            return [Member(item.filename,item.uncompressed,member_read(item.filename),item.compressed,False) for item in infos]
        except Exception as error:
            last=error
    # py7zr lacks some filters (BCJ2, ARM64, Deflate64) and encrypted-header variants that 7-Zip itself reads.
    try:return tool_members(data,'.7z')
    except RuntimeError:pass
    raise RuntimeError('7z archive could not be opened: '+type(last).__name__)


def rar_members(data):
    try:import rarfile
    except ImportError:raise RuntimeError('RAR support unavailable: install rarfile') from None
    # rarfile reads headers itself; 7-Zip (which reads RAR) only decompresses members.
    tool=seven_zip_tool()
    if tool:
        rarfile.SEVENZIP_TOOL=tool
        rarfile.tool_setup(unrar=False,unar=False,bsdtar=False,sevenzip=True,sevenzip2=False,force=True)
    elif not (shutil.which('unrar') or shutil.which('unrar.exe')):
        raise RuntimeError('RAR members were not inspected: no unrar tool is installed')
    archive=rarfile.RarFile(io.BytesIO(data))
    result=[]
    for info in archive.infolist():
        if info.is_dir():continue
        def read(limit,item=info):
            passwords=(None,) if not item.needs_password() else tuple(p.decode() for p in SHARING_PASSWORDS)
            last=None
            for password in passwords:
                try:
                    with archive.open(item,pwd=password) as stream:return stream.read(limit+1)
                except rarfile.Error as error:last=error
            raise RuntimeError('RAR member could not be opened: '+type(last).__name__)
        result.append(Member(info.filename,info.file_size,read,info.compress_size,info.needs_password()))
    return result


MSI_CLSID='000C1084-0000-0000-C000-000000000046'
MSI_CHARS='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'


def msi_name(name):
    """Windows Installer packs two name characters into one code point; tables start with U+4840."""
    out=[]
    for ch in name:
        code=ord(ch)
        if 0x3800<=code<0x4800:code-=0x3800;out+=[MSI_CHARS[code&0x3f],MSI_CHARS[(code>>6)&0x3f]]
        elif 0x4800<=code<0x4840:out.append(MSI_CHARS[code-0x4800])
        elif code==0x4840:out.append('!')
        else:out.append(ch)
    return ''.join(out)


def msi_strings(package):
    """The string pool, one string per line. Strings are stored back to back, so a rule must not read across two of them."""
    streams={msi_name(path[0]):path for path in package.listdir(streams=True,storages=False) if len(path)==1}
    pool,raw=(package.openstream(streams[name]).read(64*1024*1024) for name in ('!_StringPool','!_StringData'))
    words=[int.from_bytes(pool[k:k+2],'little') for k in range(0,len(pool)-1,2)]
    lines,offset,i=[],0,1
    while i*2+1<len(words) and offset<=len(raw):
        if words[i*2]==0 and words[i*2+1]==0:i+=1;continue
        if words[i*2]==0:
            if i*2+3>=len(words):break
            size=(words[i*2+3]<<16)+words[i*2+2];i+=2  # strings over 64 KB keep the high word in the next entry
        else:size=words[i*2];i+=1
        lines.append(raw[offset:offset+size].replace(b'\n',b' ').replace(b'\r',b' '));offset+=size
    return b'\n'.join(lines)


def msi_members(data):
    """Streams of a Windows Installer package: embedded cabinets and Binary-table programs and scripts.
    Custom-action command lines live in the string pool, which is offered as one text member."""
    import olefile
    package=olefile.OleFileIO(io.BytesIO(data))
    result=[]
    for path in package.listdir(streams=True,storages=False):
        name=msi_name('/'.join(path))
        # Signature and summary streams and database tables hold no code.
        if '/\x05' in '/'+name or '/!' in '/'+name:continue
        def read(limit,item=path):
            with package.openstream(item) as stream:return stream.read(limit+1)
        result.append(Member(name,package.get_size(path),read))
    try:strings=msi_strings(package)
    except (OSError,ValueError,KeyError):strings=b''
    # A script suffix lets the script rules read custom-action commands.
    if strings:result.append(Member('msi-strings.cmd',len(strings),lambda limit:strings[:limit+1]))
    return result


READERS={'msi':msi_members,'cab':cab_members,'zip':zip_members,'apk':zip_members,'jar':zip_members,'tar':tar_members,'gzip':_stream(_gzip_engine,'gzip-content'),
    'bzip2':_stream(_bz2_engine,'bzip2-content'),'xz':_stream(_xz_engine,'xz-content'),'7z':seven_zip_members,'rar':rar_members}
