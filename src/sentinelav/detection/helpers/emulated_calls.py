# Purpose: Implement virtual Win32 API effects inside the bounded emulator.
# Works with: detection.helpers.emulation_errors
# Used by: detection.helpers.winapi_emulator

"""In-memory Win32 API model for a bounded Unicorn analysis pass.

No host files, registry, network, processes or DLLs are accessed by guest APIs.
Unsupported semantics stop analysis instead of fabricating successful execution.
"""

import struct
from .emulation_errors import UnsupportedAPI


class EmulatedCallsMixin:
    """Fake implementations of the Windows API functions an emulated program may call.

    The emulator runs a program's machine code in a sandbox, and whenever the program calls a
    Windows function it lands here instead of in real Windows. Files, registry keys and network
    connections only exist as virtual, in-memory objects, and interesting calls are recorded as
    events (file writes, registry writes, network attempts). Anything we do not model raises
    UnsupportedAPI, which stops the emulation honestly rather than pretending the call succeeded.
    """

    def invoke(self, name, a):
        # Memory management: hand out memory from the emulator's own bounded pool.
        """Carry out one emulated Windows API call.

        name is the lower-case function name and a is the list of its arguments. Returns the value
        the real function would return (for example a handle, a byte count, or 1 for success).
        """
        if name == 'virtualalloc':
            return self.allocate(a[1], a[0])
        if name == 'heapalloc':
            return self.allocate(max(1, a[2]))
        if name in ('virtualfree', 'heapfree'):
            self.omissions.append('Emulated frees retain mappings within the allocation budget')
            return 1
        if name == 'virtualprotect':
            self.read(a[0], min(a[1], 4096))
            self.write(a[3], struct.pack('<I', 0x04))
            self.event('memory_protection', address=a[0], size=a[1], protection=a[2])
            return 1
        if name == 'getprocessheap':
            return 0x100
        # Module loading: pretend to load DLLs and hand back a fake handle.
        if name in ('loadlibrarya', 'loadlibraryw', 'getmodulehandlea', 'getmodulehandlew'):
            if name.startswith('getmodulehandle') and not a[0]:
                return self.image_base
            value = self.text(a[0], name.endswith('w'))
            self.event('module_lookup', name=value[:260])
            return self.module(value or 'subject.exe')
        if name == 'getprocaddress':
            module = self.handles.get(a[0], {})
            if module.get('kind') != 'module' or a[1] < 65536:
                raise UnsupportedAPI('Unknown module or ordinal resolution')
            symbol = self.text(a[1])
            if symbol.casefold() not in self.ARGUMENTS:
                raise UnsupportedAPI('Dynamic API ' + symbol)
            return self.bind(module['value'], symbol)
        if name == 'getlasterror':
            return self.error
        if name == 'setlasterror':
            self.error = a[0]
            return 0
        if name == 'getcurrentprocess':
            return (1 << (8 * self.width)) - 1
        if name == 'getcurrentprocessid':
            return 42
        if name == 'getcurrentthreadid':
            return 43
        if name == 'isdebuggerpresent':
            return 0
        if name == 'checkremotedebuggerpresent':
            self.write(a[1], struct.pack('<I', 0))
            return 1
        # Environment queries get fixed, believable answers so the program carries on.
        if name.startswith('getmodulefilename'):
            if a[0] not in (0, self.image_base):
                raise UnsupportedAPI('Module filename for unmodeled DLL image')
            return self.output_text(a[1], a[2], 'C:\\Sample\\subject.exe', name.endswith('w'))
        if name.startswith('getcommandline'):
            if name not in self.strings:
                value = '"C:\\Sample\\subject.exe"'.encode(
                    'utf-16le' if name.endswith('w') else 'utf-8'
                ) + (b'\0\0' if name.endswith('w') else b'\0')
                address = self.allocate(len(value))
                self.write(address, value)
                self.strings[name] = address
            return self.strings[name]
        if name.startswith('getenvironmentvariable'):
            environment = {
                'systemroot': 'C:\\Windows',
                'windir': 'C:\\Windows',
                'temp': 'C:\\Temp',
                'tmp': 'C:\\Temp',
                'userprofile': 'C:\\Users\\Analyst',
            }
            value = environment.get(self.text(a[0], name.endswith('w')).casefold())
            if value is None:
                self.error = 203
                return 0
            if a[2] <= len(value):
                return len(value) + 1
            return self.output_text(a[1], a[2], value, name.endswith('w'))
        if name.startswith(('gettemppath', 'getwindowsdirectory', 'getsystemdirectory')):
            if name.startswith('gettemppath'):
                value = 'C:\\Temp\\'
            elif name.startswith('getsystemdirectory'):
                value = 'C:\\Windows\\System32'
            else:
                value = 'C:\\Windows'
            capacity, address = (a[0], a[1]) if name.startswith('gettemppath') else (a[1], a[0])
            if capacity <= len(value):
                return len(value) + 1
            return self.output_text(address, capacity, value, name.endswith('w'))
        if name == 'getsystemtimeasfiletime':
            self.write(a[0], struct.pack('<Q', 132537600000000000 + self.virtual_ms * 10000))
            return 0
        if name == 'queryperformancecounter':
            self.write(a[0], struct.pack('<Q', self.virtual_ms * 10000))
            return 1
        if name == 'queryperformancefrequency':
            self.write(a[0], struct.pack('<Q', 10000000))
            return 1
        if name == 'getversion':
            return 10
        if name in (
            'initializecriticalsection',
            'entercriticalsection',
            'leavecriticalsection',
            'deletecriticalsection',
        ):
            if 'Single-threaded synchronization model' not in self.omissions:
                self.omissions.append('Single-threaded synchronization model')
            return 0
        if name == 'tlsalloc':
            if self.next_tls >= 128:
                self.error = 8
                return 0xFFFFFFFF
            index = self.next_tls
            self.next_tls += 1
            self.tls[index] = 0
            return index
        if name == 'tlsgetvalue':
            return self.tls.get(a[0], 0)
        if name == 'tlssetvalue':
            if a[0] not in self.tls:
                self.error = 87
                return 0
            self.tls[a[0]] = a[1]
            return 1
        if name == 'tlsfree':
            return int(self.tls.pop(a[0], None) is not None)
        if name.startswith('getstartupinfo'):
            size = 104 if self.wide else 68
            self.write(a[0], struct.pack('<I', size) + bytes(size - 4))
            return 0
        # Sleeping only moves the virtual clock forward; no real time passes.
        if name == 'sleep':
            self.virtual_ms += min(a[0], 300000)
            self.event('virtual_sleep', milliseconds=a[0])
            return 0
        if name in ('gettickcount', 'gettickcount64'):
            return self.virtual_ms
        if name in ('exitprocess', 'exitthread'):
            self.exited = True
            self.event('exit', code=a[0])
            return 0
        if name in ('memcpy', 'memmove', 'rtlmovememory'):
            self.write(a[0], self.read(a[1], a[2]))
            return a[0]
        if name == 'memset':
            if a[2] > 4 * 1024 * 1024:
                raise ValueError('Emulated memset size cap')
            self.write(a[0], bytes([a[1] & 255]) * a[2])
            return a[0]
        if name in ('lstrlena', 'lstrlenw'):
            return len(self.text(a[0], name.endswith('w')))
        # Files exist only in a virtual in-memory file system.
        if name in ('createfilea', 'createfilew'):
            path = self.text(a[0], name.endswith('w')).casefold()
            if a[4] not in (1, 2, 3, 4, 5):
                raise UnsupportedAPI('Unmodeled CreateFile disposition')
            if path not in self.files and a[4] in (3, 5):
                self.error = 2
                return -1
            if path in self.files and a[4] == 1:
                self.error = 80
                return -1
            if path not in self.files:
                if len(self.files) >= 128:
                    raise ValueError('Virtual file count cap')
                self.files[path] = bytearray()
            if a[4] in (2, 5):
                self.file_bytes -= len(self.files[path])
                self.files[path] = bytearray()
            self.event('file_open', path=path[:512])
            return self.handle('file', path)
        if name in ('readfile', 'writefile'):
            handle = self.handles.get(a[0], {})
            if handle.get('kind') != 'file':
                self.error = 6
                return 0
            if a[4]:
                raise UnsupportedAPI('Overlapped file I/O')
            content = self.files.get(handle['value'])
            position = handle['position']
            if content is None:
                raise UnsupportedAPI('I/O on a moved/deleted virtual file handle')
            if name == 'readfile':
                length = min(a[2], max(0, len(content) - position))
                self.write(a[1], content[position : position + length])
            else:
                payload = self.read(a[1], a[2])
                length = len(payload)
                growth = max(0, position + length - len(content))
                if self.file_bytes + growth > 8 * 1024 * 1024:
                    raise ValueError('Virtual file byte cap')
                content.extend(bytes(growth))
                content[position : position + length] = payload
                self.file_bytes += growth
                self.event('file_write', path=handle['value'][:512], bytes=length)
            handle['position'] += length
            if a[3]:
                self.write(a[3], struct.pack('<I', length))
            return 1
        if name == 'closehandle':
            return int(self.handles.pop(a[0], None) is not None)
        if name in ('deletefilea', 'deletefilew'):
            path = self.text(a[0], name.endswith('w')).casefold()
            if path not in self.files:
                self.error = 2
                return 0
            self.file_bytes -= len(self.files.pop(path))
            self.event('file_delete', path=path[:512])
            return 1
        if name in ('movefilea', 'movefilew'):
            source = self.text(a[0], name.endswith('w')).casefold()
            target = self.text(a[1], name.endswith('w')).casefold()
            if source not in self.files or target in self.files:
                self.error = 2
                return 0
            self.files[target] = self.files.pop(source)
            self.event('file_move', source=source[:512], target=target[:512])
            return 1
        # Registry writes are recorded, not performed; the Run key ones matter most for spotting
        # persistence.
        if name in ('regcreatekeyexa', 'regcreatekeyexw'):
            path = self.text(a[1], name.endswith('w'))
            handle = self.handle('registry', path)
            self.store_pointer(a[7], handle)
            if a[8]:
                self.write(a[8], struct.pack('<I', 1))
            self.event('registry_open', path=path[:512])
            return 0
        if name in ('regsetvalueexa', 'regsetvalueexw'):
            key = self.handles.get(a[0], {})
            if key.get('kind') != 'registry':
                return 6
            self.read(a[4], min(a[5], 4096))
            self.event(
                'registry_write',
                path=str(key['value'])[:512],
                value=self.text(a[1], name.endswith('w'))[:256],
                bytes=a[5],
            )
            return 0
        if name == 'regclosekey':
            self.handles.pop(a[0], None)
            return 0
        # Networking: note where the program wants to connect, then make every request fail.
        if name == 'winhttpopen':
            return self.handle('http_session', 'virtual')
        if name == 'winhttpconnect':
            if self.handles.get(a[0], {}).get('kind') != 'http_session':
                self.error = 6
                return 0
            host = self.text(a[1], True)
            self.event('network_intent', host=host[:253], port=a[2])
            return self.handle('http_connection', host)
        if name == 'winhttpopenrequest':
            if self.handles.get(a[0], {}).get('kind') != 'http_connection':
                self.error = 6
                return 0
            return self.handle('http_request', 'virtual')
        if name == 'winhttpsendrequest':
            self.error = 12029
            self.event('network_blocked')
            return 0
        if name == 'winhttpclosehandle':
            return int(self.handles.pop(a[0], None) is not None)
        raise UnsupportedAPI(name)
