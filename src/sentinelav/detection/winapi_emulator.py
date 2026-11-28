# Purpose: In-memory Win32 API model for a bounded Unicorn analysis pass.
# Works with: detection.emulated_calls, detection.emulation_errors
# Used by: detection.windows_emulation

"""In-memory Win32 API model for a bounded Unicorn analysis pass.

No host files, registry, network, processes or DLLs are accessed by guest APIs.
Unsupported semantics stop analysis instead of fabricating successful execution.
"""

import struct


from .emulation_errors import UnsupportedAPI


from .emulated_calls import EmulatedCallsMixin


class WinAPIModel(EmulatedCallsMixin):
    # Stack argument counts are ABI descriptions, not malware-specific rules.
    """The small, self-made Windows environment used by the 'minimal' emulator.

    Every import of the emulated program is pointed at a tiny 'stub' address. When the program jumps
    to a stub, dispatch() reads the call's arguments, runs our fake implementation (from
    EmulatedCallsMixin), puts the return value in the right register and returns to the caller, just
    as a real Windows function would. All state (heap, files, handles) is virtual and capped.
    """
    ARGUMENTS = {
        'virtualalloc': 4,
        'virtualfree': 3,
        'virtualprotect': 4,
        'getprocessheap': 0,
        'heapalloc': 3,
        'heapfree': 3,
        'loadlibrarya': 1,
        'loadlibraryw': 1,
        'getmodulehandlea': 1,
        'getmodulehandlew': 1,
        'getprocaddress': 2,
        'getlasterror': 0,
        'setlasterror': 1,
        'getcurrentprocess': 0,
        'getcurrentprocessid': 0,
        'getcurrentthreadid': 0,
        'sleep': 1,
        'gettickcount': 0,
        'gettickcount64': 0,
        'exitprocess': 1,
        'exitthread': 1,
        'memcpy': 3,
        'memmove': 3,
        'rtlmovememory': 3,
        'memset': 3,
        'lstrlena': 1,
        'lstrlenw': 1,
        'createfilea': 7,
        'createfilew': 7,
        'readfile': 5,
        'writefile': 5,
        'closehandle': 1,
        'deletefilea': 1,
        'deletefilew': 1,
        'movefilea': 2,
        'movefilew': 2,
        'regcreatekeyexa': 9,
        'regcreatekeyexw': 9,
        'regsetvalueexa': 6,
        'regsetvalueexw': 6,
        'regclosekey': 1,
        'winhttpopen': 5,
        'winhttpconnect': 4,
        'winhttpopenrequest': 7,
        'winhttpsendrequest': 7,
        'winhttpclosehandle': 1,
        'isdebuggerpresent': 0,
        'checkremotedebuggerpresent': 2,
        'getmodulefilenamea': 3,
        'getmodulefilenamew': 3,
        'getcommandlinea': 0,
        'getcommandlinew': 0,
        'getenvironmentvariablea': 3,
        'getenvironmentvariablew': 3,
        'gettemppatha': 2,
        'gettemppathw': 2,
        'getwindowsdirectorya': 2,
        'getwindowsdirectoryw': 2,
        'getsystemdirectorya': 2,
        'getsystemdirectoryw': 2,
        'getsystemtimeasfiletime': 1,
        'queryperformancecounter': 1,
        'queryperformancefrequency': 1,
        'getversion': 0,
        'initializecriticalsection': 1,
        'entercriticalsection': 1,
        'leavecriticalsection': 1,
        'deletecriticalsection': 1,
        'tlsalloc': 0,
        'tlsgetvalue': 1,
        'tlssetvalue': 2,
        'tlsfree': 1,
        'getstartupinfoa': 1,
        'getstartupinfow': 1,
    }

    def __init__(self, machine, wide, registers, stub_base, heap_base, image_base=0):
        """Set up an empty virtual environment on top of a Unicorn CPU (machine), with regions reserved
        for import stubs and the heap.
        """
        self.machine, self.wide, self.reg = machine, wide, registers
        self.width = 8 if wide else 4
        self.stub_base, self.heap_base = stub_base, heap_base
        self.next_heap = heap_base
        self.heap_bytes = 0
        self.stubs = {}
        self.reverse = {}
        self.modules = {}
        self.handles = {}
        self.next_handle = 0x1000
        self.files = {}
        self.file_bytes = 0
        self.error = 0
        self.virtual_ms = 1000
        self.events = []
        self.calls = 0
        self.exited = False
        self.omissions = []
        self.image_base = image_base
        self.strings = {}
        self.tls = {}
        self.next_tls = 0

    def output_text(self, address, capacity, text, wide=False):
        """Write a string into the program's buffer like a Windows API would, failing (error 122,
        buffer too small) when it does not fit.
        """
        if not 0 <= capacity <= 32768:
            raise ValueError('Emulated string output capacity')
        if capacity <= len(text):
            self.error = 122
            return 0
        self.write(
            address, text.encode('utf-16le' if wide else 'utf-8') + (b'\0\0' if wide else b'\0')
        )
        return len(text)

    def event(self, kind, **fields):
        """Record one interesting action (file write, registry write, network attempt, ...), keeping at
        most 256.
        """
        if len(self.events) < 256:
            self.events.append(dict(kind=kind, **fields))

    def read(self, address, size):
        """Read bytes from emulated memory (at most 4 MB at once)."""
        if not 0 <= size <= 4 * 1024 * 1024:
            raise ValueError('Emulated memory operation exceeds limit')
        return bytes(self.machine.mem_read(address, size))

    def write(self, address, data):
        """Write bytes into emulated memory (at most 4 MB at once)."""
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('Emulated write exceeds limit')
        self.machine.mem_write(address, bytes(data))

    def pointer(self, address):
        """Read one pointer-sized number from emulated memory."""
        return int.from_bytes(self.read(address, self.width), 'little')

    def store_pointer(self, address, value):
        """Write one pointer-sized number into emulated memory."""
        self.write(address, int(value).to_bytes(self.width, 'little', signed=False))

    def text(self, address, wide=False):
        """Read a zero-terminated string (ANSI, or UTF-16 if wide) from emulated memory."""
        if not address:
            return ''
        output = bytearray()
        width = 2 if wide else 1
        for index in range(4096):
            unit = self.read(address + index * width, width)
            if unit == bytes(width):
                return output.decode('utf-16le' if wide else 'utf-8', errors='replace')
            output.extend(unit)
        raise ValueError('Emulated string exceeds limit')

    def allocate(self, size, address=0):
        """Hand out a fresh block from the virtual heap, rounded up to whole 4 KB pages, within a 32 MB
        budget.
        """
        if not 0 < size <= 16 * 1024 * 1024:
            raise ValueError('Emulated allocation size cap')
        size = (size + 4095) & ~4095
        if self.heap_bytes + size > 32 * 1024 * 1024:
            raise ValueError('Emulated heap budget')
        if address:
            if address != self.next_heap:
                raise UnsupportedAPI('Fixed-address allocation outside modeled heap')
        address = self.next_heap
        self.next_heap += size
        self.heap_bytes += size
        self.machine.mem_map(address, size)
        return address

    def handle(self, kind, value):
        """Create a new fake handle for a file, registry key, module or network object."""
        self.next_handle += 1
        self.handles[self.next_handle] = dict(kind=kind, value=value, position=0)
        return self.next_handle

    def module(self, name):
        """Return the fake module handle for a DLL name, creating it on first use."""
        name = name.replace('\\', '/').rsplit('/', 1)[-1].casefold()
        if len(self.modules) >= 128 and name not in self.modules:
            raise ValueError('Emulated module cap')
        if name not in self.modules:
            self.modules[name] = self.handle('module', name)
        return self.modules[name]

    def bind(self, library, name):
        """Return the stub address for a library function, creating a new stub on first use."""
        key = (library.casefold(), name.casefold())
        if key not in self.reverse:
            if len(self.stubs) >= 2048:
                raise ValueError('Emulated import stub cap')
            address = self.stub_base + len(self.stubs) * 16
            self.stubs[address] = (library, name)
            self.reverse[key] = address
        return self.reverse[key]

    def arguments(self, count):
        """Read a call's arguments from the stack (32-bit) or from registers and stack (64-bit calling
        convention).
        """
        stack = self.machine.reg_read(
            self.reg.UC_X86_REG_RSP if self.wide else self.reg.UC_X86_REG_ESP
        )
        if not self.wide:
            return stack, [self.pointer(stack + 4 + i * 4) for i in range(count)]
        registers = (
            self.reg.UC_X86_REG_RCX,
            self.reg.UC_X86_REG_RDX,
            self.reg.UC_X86_REG_R8,
            self.reg.UC_X86_REG_R9,
        )
        return stack, [
            self.machine.reg_read(registers[i]) if i < 4 else self.pointer(stack + 40 + (i - 4) * 8)
            for i in range(count)
        ]

    def dispatch(self, address):
        """Handle a call to a stub: run the fake API, set the return value, clean up the stack and
        return to the caller.
        """
        library, name = self.stubs[address]
        dll = library.replace('\\', '/').rsplit('/', 1)[-1].casefold()
        if dll not in {
            'kernel32.dll',
            'kernelbase.dll',
            'ntdll.dll',
            'advapi32.dll',
            'winhttp.dll',
            'msvcrt.dll',
            'ucrtbase.dll',
            'vcruntime140.dll',
            'vcruntime140_1.dll',
        } and not dll.startswith(('api-ms-win-', 'ext-ms-win-')):
            raise UnsupportedAPI('Non-system DLL semantics are not modeled: ' + library)
        key = name.casefold()
        if key not in self.ARGUMENTS:
            raise UnsupportedAPI(library + '!' + name)
        self.calls += 1
        if self.calls > 4096:
            raise ValueError('Emulated API call budget')
        stack, args = self.arguments(self.ARGUMENTS[key])
        result = self.invoke(key, args)
        if self.exited:
            self.machine.emu_stop()
            return
        return_address = self.pointer(stack)
        # C runtime memory/string imports use cdecl in x86; Win32 APIs stdcall.
        cdecl = key in ('memcpy', 'memmove', 'memset') or library.casefold().startswith(
            ('msvcr', 'ucrt', 'vcruntime')
        )
        adjustment = self.width + (0 if self.wide or cdecl else len(args) * self.width)
        self.machine.reg_write(
            self.reg.UC_X86_REG_RAX if self.wide else self.reg.UC_X86_REG_EAX,
            result & ((1 << (8 * self.width)) - 1),
        )
        self.machine.reg_write(
            self.reg.UC_X86_REG_RSP if self.wide else self.reg.UC_X86_REG_ESP, stack + adjustment
        )
        self.machine.reg_write(
            self.reg.UC_X86_REG_RIP if self.wide else self.reg.UC_X86_REG_EIP, return_address
        )
