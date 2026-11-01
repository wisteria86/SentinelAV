"""Small bounded PE-header inspector. No unpacking or executable loading."""
import struct


def pe_metadata(data):
    if not data.startswith(b'MZ'): return dict(format='Other')
    if len(data)<64: raise ValueError('Truncated DOS/PE header')
    offset=struct.unpack_from('<I',data,0x3c)[0]
    if offset>1024*1024 or offset+24>len(data) or data[offset:offset+4]!=b'PE\0\0':
        raise ValueError('Invalid or unsupported PE-header offset/signature')
    machine,sections=struct.unpack_from('<HH',data,offset+4)
    optional_size=struct.unpack_from('<H',data,offset+20)[0]
    table=offset+24+optional_size
    if not 1<=sections<=96 or optional_size>4096 or table+sections*40>len(data):
        raise ValueError('PE section-table bounds exceeded')
    result=[]
    for index in range(sections):
        start=table+index*40
        name=data[start:start+8].split(b'\0')[0].decode('ascii',errors='replace')
        raw_size,raw_offset=struct.unpack_from('<II',data,start+16)
        if raw_size and raw_offset+raw_size>len(data): raise ValueError('PE section exceeds inspected file bounds')
        result.append(dict(name=name,raw_bytes=raw_size))
    return dict(format='PE',machine=hex(machine),sections=result,unpacked=False)
