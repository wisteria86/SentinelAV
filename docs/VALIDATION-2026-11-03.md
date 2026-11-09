# Integration validation — 2026-11-03

**Follow-up:** the packaged-emulator blocker below was resolved in a subsequent
local native build. All 159 unit tests and four frozen emulator regression cases
passed, and the rebuilt application's core and advanced self-tests passed.
CFG remains enabled. See [native build details](../native/emulator/README.md).
The results below preserve the earlier validation snapshot; the corresponding
new evidence is `artifacts/evaluations/emulator-validation-20261103.json`.

**Result: source and core packaged checks pass; packaged emulation is unavailable.**
These results validate specific operational paths, not protection against a
representative malware population. No real malware was executed.

| Check | Result |
| --- | --- |
| Python compilation / PowerShell parsing | Pass |
| Unit suite | 156 tests passed |
| Qt application integration | All 11 scripts passed |
| Native telemetry | .NET 8.0.427 build: zero warnings/errors; dependency self-check passed; ETW was not started |
| Source emulator | Harmless x86/x64 import dispatch, allocation/write inspection, unsupported-API omission and TLS return passed |
| Frozen application | Core self-test passed, including real scanner workers, UI, encrypted quarantine/restore, exports and decoded marker detection |
| Frozen emulator | Unavailable under CFG; explicitly reported as partial coverage, not a passing emulation check |
| System32 sample | 200 inspected files, zero signature detections/errors/skips, 8.1289 seconds; labels presumed benign |
| Offline guest lifecycle | Microsoft-signed guest whoami copied and executed only in the guest; bounded numeric host summary and registered-guest disposal/reset verified |

## Failures found and repaired

- TLS return could make Unicorn translate past the stub arena into unmapped memory.
  A bounded return sentinel fixes the fault; the regression executes only inside
  the emulator, never through Windows' executable loader.
- Frozen analysis missed Unicorn's native DLL and dynamically imported architecture
  modules. Explicit binary/submodule collection fixes those packaging omissions.
- Native collector settings were read with the wrong Store.get call signature;
  both foreground and background paths now pass the required default.
- Process-tree execution trusted input ordering. It now derives child-first order
  from the freshly observed tree; tests mock termination and never kill real users'
  processes.
- Guest cleanup failed when Windows PowerShell inherited an incompatible module
  path. Native module-path initialization fixes Get-FileHash resolution. Reset
  diagnostics are retained, and guest bootstrap readiness is awaited explicitly.
- Analysis settings clipped at 960×600. Scrollable content and compact-layout
  assertions now cover that page.
- The filesystem-only UI lifecycle test mixed in unrelated process telemetry.
  It now tests its controlled filesystem source; process behavior remains covered
  separately, rather than incorrectly expecting unrelated omissions to disappear.

## Remaining packaged-emulator issue

The current Unicorn 2.1.4 Windows library fails fast inside a CFG-enabled
PyInstaller process. It succeeds under the tested source Python runtime, including
the existing bounded scan worker. A compatibility check now reports the frozen
feature unavailable before entering native emulation, preserving scanner stability
and keeping mitigations enabled. No CFG flag or Windows security setting was changed.

Primary references:
- https://github.com/unicorn-engine/unicorn/issues/2281
- https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html

The packaged self-test records core `PASS` and advanced `PARTIAL`; the report does
not count unavailable emulation as passed. A compatible native emulator build or
backend is still required for that feature in the hardened frozen application.

## Scope and evidence

The guest had no Sysmon source, so its runtime summary has zero telemetry events
and two omissions. That check proves controlled launch/observation/disposal, not
behavioral malware detection. The used guest was discarded and a fresh baseline
verified. No host service/provider/policy was installed, and live ETW collection,
AMSI deployment and host enforcement remain outside this run.

Testing installed Unicorn 2.1.4 and oletools 0.60.2 into the existing virtual
environment, and a checksum-verified .NET SDK under ignored tools/vendor. SDK
first-run setup unexpectedly created an untrusted localhost development certificate;
that exact new certificate/key was removed. Future builds suppress its generation.
No Windows root trust or protection configuration was changed.

Evidence is local and ignored by Git:

- `artifacts/evaluations/integration-validation-20261103.json` — combined record and source hashes.
- `artifacts/validation-build/validation-evidence.json` — final frozen executable hash and self-test location.
- `artifacts/evaluations/benign-20261103T140809Z-2725059e/report.json` — System32 inventory and results.
- `artifacts/lab/runtime-validation/c55b8c8a84d8464abf11b7d3659050f1/validation.json` — safe guest lifecycle evidence.

The separate validation bundle is under `artifacts/validation-build/dist/SentinelAV`.
The previous release installer was not replaced or published. Earlier real-sample
misses remain misses; no new hashes or claimed malware detection rate were added.
