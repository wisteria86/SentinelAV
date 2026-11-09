# Purpose: Bounded PE import decoding. No loader calls, emulation or symbol resolution.
# Works with: sibling modules in detection
# Used by: detection.file_formats, tests.unit.test_pe_imports

"""Bounded PE import decoding. No loader calls, emulation or symbol resolution."""
import struct


def inspect_imports(data,metadata):
    progress=dict(libraries=[],functions=0)
    try:return _inspect_imports(data,metadata,progress)
    except ValueError as error:
        if not progress['libraries']:raise
        return dict(status='Incomplete',reason=str(error),partial=True,delay_imports_inspected=False,**progress)


def _inspect_imports(data, metadata,progress):
    offset=struct.unpack_from('<I',data,0x3c)[0]
    optional=offset+24
    size=struct.unpack_from('<H',data,offset+20)[0]
    if size<2: return dict(status='Unavailable',reason='Missing optional header',libraries=[])
    magic=struct.unpack_from('<H',data,optional)[0]
    if magic not in (0x10b,0x20b):
        return dict(status='Unavailable',reason='Unsupported optional header',libraries=[])
    directory_offset,count_offset,width=(96,92,4) if magic==0x10b else (112,108,8)
    if size<count_offset+4: raise ValueError('Truncated PE directory count')
    count=struct.unpack_from('<I',data,optional+count_offset)[0]
    if count<2: return dict(status='Complete',libraries=[],functions=0,delay_imports_inspected=False)
    if size<directory_offset+16: raise ValueError('Truncated import directory')
    rva,directory_size=struct.unpack_from('<II',data,optional+directory_offset+8)
    if not rva and not directory_size:
        return dict(status='Complete',libraries=[],functions=0,delay_imports_inspected=False)
    if not rva or directory_size<20: raise ValueError('Invalid import directory bounds')
    if size<64: raise ValueError('Missing SizeOfHeaders')
    header_bytes=struct.unpack_from('<I',data,optional+60)[0]

    def locate(address,length):
        matches=[]
        if address<header_bytes and address+length<=min(header_bytes,len(data)):
            matches.append((address,min(header_bytes,len(data))))
        for section in metadata['sections']:
            relative=address-section['virtual_address']
            if 0<=relative and relative+length<=section['raw_bytes']:
                start=section['raw_offset']+relative
                matches.append((start,section['raw_offset']+section['raw_bytes']))
        if len(matches)!=1: raise ValueError('Unmapped or ambiguous import RVA')
        start,end=matches[0]
        if start+length>len(data): raise ValueError('Import exceeds file bounds')
        return start,end

    name_bytes=0
    def string(address):
        nonlocal name_bytes
        start,end=locate(address,1)
        end=min(end,start+512)
        stop=data.find(b'\0',start,end)
        if stop<0: raise ValueError('Unterminated or oversized import name')
        value=bytes(data[start:stop])
        name_bytes+=len(value)
        if name_bytes>64*1024: raise ValueError('Import name budget exceeded')
        if not value or any(v<32 or v>126 for v in value): raise ValueError('Invalid import name')
        return value.decode('ascii')

    libraries=progress['libraries']
    functions=0
    for index in range(min(directory_size//20,257)):
        if index==256: raise ValueError('Import library limit exceeded')
        descriptor,_=locate(rva+index*20,20)
        original,stamp,chain,name,first=struct.unpack_from('<IIIII',data,descriptor)
        if not any((original,stamp,chain,name,first)):
            return dict(status='Complete',libraries=libraries,functions=functions,delay_imports_inspected=False)
        library=string(name)
        symbols=[]
        libraries.append(dict(name=library,symbols=symbols))
        thunk=original or first
        if not thunk: raise ValueError('Missing import thunk')
        for number in range(4097):
            if number==4096 or functions>=8192: raise ValueError('Import symbol limit exceeded')
            pointer,_=locate(thunk+number*width,width)
            value=struct.unpack_from('<I' if width==4 else '<Q',data,pointer)[0]
            if not value: break
            ordinal=bool(value & (1<<(width*8-1)))
            symbols.append(dict(ordinal=value & 0xffff) if ordinal else dict(name=string(value+2)))
            functions+=1
            progress['functions']=functions
    raise ValueError('Unterminated import directory')


def capability_evidence(imports):
    """API groups are descriptive evidence, not a malicious-API blacklist."""
    names={symbol['name'].casefold() for library in imports.get('libraries',[])
           for symbol in library['symbols'] if 'name' in symbol}
    groups={
        'cross_process_memory':({'openprocess'},{'virtualallocex'},{'writeprocessmemory'}),
        'remote_thread':({'createremotethread','createremotethreadex','ntcreatethreadex'},),
        'registry_write':({'regsetvalueexa','regsetvalueexw'},),
        'network_client':({'internetconnecta','internetconnectw','winhttpconnect','connect','wsaconnect'},),
        'cryptography':({'cryptencrypt','bcryptencrypt'},),
    }
    return [dict(capability=key,matched_imports=sorted(set.union(*(names & options for options in required))))
            for key,required in groups.items() if all(names & options for options in required)]
