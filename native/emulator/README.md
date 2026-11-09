# Windows emulator build

Unicorn 2.1.4's upstream Windows wrapper hides `setjmp` from the compiler and
uses a null unwind frame. In a CFG-enabled frozen process this fails fast.
The local patch keeps compiler-visible `setjmp`, retains the normal unwind
frame, and registers unwind information for the generated x64 host frames.
Both emulated x86 and x64 use this x64 host backend.

The unwind codes are generated from the actual push offsets, saved register
list, and stack allocation in the TCG prologue. The metadata occupies a
reserved prefix outside generated code. The function table is unregistered
before its allocation is freed. Failure to register stops the isolated worker;
it never falls back to disabling validation. This is a local prototype patch,
not an upstream-supported Unicorn fix.

## Reproduce

Requires Windows x64, Visual Studio 2022 **Build Tools** with C++ and Windows SDK,
CMake, Git, and the project's Python environment. The full Visual Studio IDE
is unnecessary. From the project folder:

```powershell
.\.venv\Scripts\python.exe tools\build_emulator.py
.\build.ps1
# Or build both together:
.\build.ps1 -NativeEmulator
```

The build pins upstream commit `8028ec436f2d9376525352dd38ed9ed6b9f6be10`,
checks existing checkout changes, applies the reviewed patch, and builds only
the x86/x64 emulator. It enables CFG, guarded longjmp, EH continuation metadata,
CET compatibility, ASLR and DEP. No Windows mitigation policy is changed.

Output: `artifacts/native/unicorn-runtime`. The spec includes the DLL, its
SHA-256 build receipt, upstream notices and corresponding modified source ZIP.
The runtime qualifies the library actually loaded by ctypes against the bundled
path and receipt. The receipt binds build identity; it is not a substitute for
signed installer integrity or protection of the installation directory.
An absent receipt or mismatched/external DLL stays unavailable under CFG.
Future upstream versions are not automatically assumed compatible.

## Validation on 2026-11-03

- 159 unit tests passed, including receipt mismatch and external-library rejection.
- CFG-enabled frozen runner: x86/x64 API dispatch, allocation/write inspection,
  TLS callback return, and unsupported-API omission passed.
- Full frozen application self-test: core and advanced checks passed, using
  the real isolated scanner. Synthetic PE bytes were interpreted by Unicorn;
  no fixture was launched by Windows.
- An initial native probe completed 20 instances per emulated CPU mode.

The Windows API model remains intentionally bounded: an operational emulator is
not a full Windows guest and does not prove that an inspected file is safe.
Real malware efficacy, broad stress coverage and other Windows builds remain
separate evaluations. Source reference for native dynamic unwind tables:
https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable
