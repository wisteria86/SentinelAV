# Purpose: Bounded file-backed PE addressing and ordinary/delay import enumeration.
# Works with: sibling modules in detection
# Used by: detection.delay_imports, detection.image_details, detection.windows_emulation

"""Bounded file-backed PE addressing and ordinary/delay import enumeration."""
import struct


class PEImage:
    def __init__(self,data,metadata):
        self.data,self.metadata=data,metadata
        self.optional=struct.unpack_from('<I',data,0x3c)[0]+24
        self.optional_size=struct.unpack_from('<H',data,self.optional-4)[0]
        if self.optional_size<96: raise ValueError('PE optional header too short')
        self.magic=struct.unpack_from('<H',data,self.optional)[0]
        if self.magic not in (0x10b,0x20b): raise ValueError('Unsupported PE image')
        self.wide=self.magic==0x20b
        self.width=8 if self.wide else 4
        self.base=struct.unpack_from('<Q' if self.wide else '<I',data,self.optional+(24 if self.wide else 28))[0]
        self.size,self.headers=struct.unpack_from('<II',data,self.optional+56)
        self.entry=metadata.get('entrypoint_rva')
        self.directory_offset=112 if self.wide else 96
        if self.optional_size<self.directory_offset: raise ValueError('Missing data directory header')
        self.directory_count=struct.unpack_from('<I',data,self.optional+self.directory_offset-4)[0]
        if not 4096<=self.size<=64*1024*1024 or self.headers>len(data) or self.headers>self.size:
            raise ValueError('PE image/header mapping bounds')

    def directory(self,index):
        if index>=self.directory_count: return 0,0
        offset=self.directory_offset+index*8
        if offset+8>self.optional_size: raise ValueError('Truncated PE directory')
        return struct.unpack_from('<II',self.data,self.optional+offset)

    def locate(self,rva,size):
        if rva<0 or size<0 or rva+size>self.size: raise ValueError('PE virtual address out of bounds')
        locations=[]
        if rva+size<=self.headers: locations.append(rva)
        for section in self.metadata['sections']:
            relative=rva-section['virtual_address']
            if 0<=relative and relative+size<=section['raw_bytes']:
                locations.append(section['raw_offset']+relative)
        if len(locations)!=1 or locations[0]+size>len(self.data): raise ValueError('Unmapped/ambiguous PE address')
        return locations[0]

    def string(self,rva):
        value=bytearray()
        for index in range(512):
            byte=self.data[self.locate(rva+index,1)]
            if byte==0:
                if not value: raise ValueError('Empty PE name')
                return value.decode('ascii')
            if not 32<=byte<=126: raise ValueError('Invalid PE name')
            value.append(byte)
        raise ValueError('PE name length limit')

    def imports(self,delay=False):
        rva,size=self.directory(13 if delay else 1)
        if not rva and not size: return []
        stride=32 if delay else 20
        if not rva or size<stride: raise ValueError('Invalid import directory')
        result=[]; name_bytes=0
        for index in range(min(size//stride,257)):
            if index==256: raise ValueError('Import descriptor cap')
            offset=self.locate(rva+index*stride,stride)
            words=struct.unpack_from('<'+'I'*(stride//4),self.data,offset)
            if not any(words): return result
            if delay:
                attributes,name,handle,iat,lookup,bound,unload,stamp=words
                if attributes & ~1: raise ValueError('Unsupported delay-import attributes')
                if not attributes & 1:
                    name-=self.base; iat-=self.base; lookup-=self.base
            else: lookup,stamp,chain,name,iat=words
            lookup=lookup or iat
            library=self.string(name)
            name_bytes+=len(library)
            if not lookup or not iat: raise ValueError('Missing import lookup/IAT')
            for number in range(4097):
                if number==4096 or len(result)>=8192: raise ValueError('Import symbol cap')
                value=struct.unpack_from('<Q' if self.wide else '<I',self.data,self.locate(lookup+number*self.width,self.width))[0]
                if not value: break
                ordinal=bool(value & (1<<(8*self.width-1)))
                name=None if ordinal else self.string(value+2)
                name_bytes+=len(name or '')
                if name_bytes>65536: raise ValueError('Import name byte cap')
                self.locate(iat+number*self.width,self.width)
                result.append(dict(library=library,name=name,ordinal=value & 0xffff if ordinal else None,
                    iat_rva=iat+number*self.width,delay=delay))
        raise ValueError('Unterminated import directory')

    def tls_callbacks(self):
        rva,size=self.directory(9)
        if not rva and not size: return []
        required=40 if self.wide else 24
        if size<required: raise ValueError('Truncated TLS directory')
        offset=self.locate(rva,required)
        callbacks=struct.unpack_from('<Q' if self.wide else '<I',self.data,offset+3*self.width)[0]
        if not callbacks: return []
        result=[]
        for index in range(17):
            if index==16: raise ValueError('TLS callback count limit')
            position=self.locate(callbacks-self.base+index*self.width,self.width)
            address=struct.unpack_from('<Q' if self.wide else '<I',self.data,position)[0]
            if not address: return result
            relative=address-self.base
            if not any(s['executable'] and s['virtual_address']<=relative<s['virtual_address']+max(s['virtual_bytes'],s['raw_bytes']) for s in self.metadata['sections']):
                raise ValueError('TLS callback outside executable image sections')
            result.append(address)
        raise ValueError('Unterminated TLS callback array')
