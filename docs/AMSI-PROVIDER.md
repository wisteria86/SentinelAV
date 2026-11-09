# Native AMSI provider — development milestone

The x64 native provider now implements `IAntimalwareProvider`, COM factory and
lifetime handling, bounded stream reads, and a read-only buffer broker client.
Its local harness was compiled with the installed MSVC 14.44 tools and Windows
SDK 10.0.26100.0. It has now been registered and tested in the disposable Windows Sandbox guest,
including the real Windows AMSI API and a harmless PowerShell comparison. See
[GUEST-AMSI-VALIDATION.md](GUEST-AMSI-VALIDATION.md). Host registration/service
deployment remain absent. This does not establish production readiness.

## What runs now

From the project root:

```powershell
.\scripts\build-amsi.ps1 -Test
.\.venv\Scripts\python.exe -m unittest tests.unit.test_amsi_buffers -v
.\.venv\Scripts\python.exe -m tests.integration.verify_amsi_provider
```

The build writes `artifacts/native/amsi/SentinelAVAmsi.dll` and
`artifacts/native/amsi/AmsiHarness.exe`. The DLL is unsigned. The harness loads
it directly without registering it. A separately compiled copy of the provider
inside the harness can connect to a random temporary test pipe; the production
DLL has no test-endpoint setter or auto-registration export.

The integration check uses harmless ordinary text, a generated exact-hash
fixture, and the existing YARA demo marker. No PowerShell payload, real malware,
script execution, antivirus reconfiguration, or registry write is involved.

## Data flow

```text
AMSI-capable host
  -> native SentinelAV COM provider (in the host process)
  -> local named pipe, authenticated against the service PID from Windows SCM
  -> LocalService buffer broker (admin-policy opt-in, currently undeployed)
  -> isolated worker: raw-byte SHA-256 / existing YARA rules
  -> detected / no match / inspection unavailable
```

`detection/buffer_scan.py` scans bytes without a file path. It neither executes
content nor calls AMSI again. It does not expand archives, quarantine anything,
or apply the filesystem response policy. Results have no response-action path.

## Bounds and failure handling

- Maximum content: 1 MiB. Oversized streams return an error, not a clean verdict.
- Stream reads: 64 KiB chunks; short successful reads are supported. Zero-byte
  premature reads, impossible read lengths, malformed size attributes, and size
  changes are rejected. For Windows address-only streams, the content address is
  copied through a bounded ReadProcessMemory call against the current process;
  invalid addresses return errors instead of being directly dereferenced.
- Four concurrent provider calls per host process; one broker connection at a
  time. This is a conservative prototype, not a high-throughput production design.
- Provider transport budget: three seconds including its stream-reading loop.
  Calls into the host's `IAmsiStream` implementation must return cooperatively;
  the provider cannot forcibly interrupt a blocked foreign COM callback.
- Broker frame/content reads are bounded; scans have an eight-second parent
  worker budget and the existing per-match YARA timeout/job memory limits.
  A client may time out before a slow worker returns; that remains an error.
- Failed/incomplete inspection is returned as a failing HRESULT. A valid hash
  finding survives a caught YARA error. If the worker crashes, the broker reports
  unavailable rather than inventing a clean result.
- No match means `AMSI_RESULT_NOT_DETECTED`, never a guarantee of safety. The
  calling host determines its handling of AMSI errors and detection results.

## Broker security boundary

Production pipe: `\\.\pipe\SentinelAV.Amsi.v1`. The server rejects remote clients,
uses first-instance protection, and runs only through the packaged LocalService
path. Authenticated clients receive read/write-data rights, not pipe-instance
creation or ACL/ownership rights. The client checks the pipe server PID against
the running `SentinelAVProtection` service via Windows SCM. It connects with
identification-level impersonation permissions; the server does not impersonate
clients. No API accepts scan paths, commands, executable names, or quarantine
instructions. Raw content and match details are not persisted by this broker;
service health contains only counters and availability.

The staged service ACL grants authenticated users SCM status-query permission
for that PID check, without start/stop or configuration permission. Detailed
health/history files retain their protected service/installer-account ACLs.

All authenticated local callers can consume the serial scanning capacity. There
are no per-client fairness quotas yet. This requires further load and abuse
testing. The worker still has its Windows account's permissions, and Windows
may page process memory; "not persisted" here is not a secure-erasure guarantee.

The service's protected `policy.json` contains `amsi_broker: false` by default.
An administrator can review changing it to true during controlled deployment.
The GUI cannot enable it. An enabled broker does not prove that a provider is
registered, signed, or successfully loaded in any real host.

## Remaining before broader deployment

1. Extend the completed LocalService/Sandbox validation to a full Windows VM
   and supported host configurations, including active antivirus coexistence.
2. Validate the existing provider-signing policy and host acceptance without
   weakening either. Purchases are excluded. If an eligible free signing route
   is used, sign the exact DLL and keep private keys outside this repository.
   See [no-purchase findings](AMSI-ZERO-COST-OPTIONS.md).
3. Generalize the guarded guest-only registration/removal tooling after further
   security review; it currently refuses ordinary host use.
4. Add and test an x86 build for 32-bit hosts; only x64 is currently built.
5. Broaden real-host latency, concurrency and failure testing. The harmless
   x64 PowerShell/API and service-recovery cases passed in the current guest.
   Defender was stopped there, so active Defender coexistence is unverified.
6. Develop and evaluate script/buffer-specific detection coverage. Existing
   rules are mostly file-oriented historical research rules. UTF-16 and other
   encodings require suitable rules; there is no automatic deobfuscator,
   cross-session reconstruction, or general AMSI-bypass detection.

No signing checks are disabled, and other providers are not removed. WDK is
not needed to build this user-mode provider. Signing/deployment work is separate
from the future kernel enforcement milestone. Broad effectiveness, VM and
live-sample evaluation remain deferred.

## Relevant files

- `native/amsi/provider.{h,cpp,def}` — production provider implementation/exports.
- `native/amsi/harness.cpp` — inert COM/stream and integration checks.
- `src/sentinelav/platform/amsi_broker.py` — local broker and guarded test endpoint.
- `src/sentinelav/detection/buffer_scan.py` — byte-only verdicts.
- `src/sentinelav/detection/inspection.py` — isolated worker buffer command.

References: [Microsoft provider interface](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider),
[stream interface](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iamsistream),
[stream read contract](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iamsistream-read).
