# First-iteration implementation contract

This historical contract is superseded for current proposal scope and validation
by [the proposal audit](PROPOSAL-AUDIT.md).

Target: an integrated Windows endpoint-protection application with real user paths,
not Defender parity or a complete emulation of Windows. Supported features must
have an implementation, an entry point, persisted results and explicit failure
states. Missing inputs must not produce fabricated protection or success.

**Validation state:** testing is now authorized. See
[integration validation](VALIDATION-2026-11-03.md): 159 unit tests pass; the earlier
11 UI checks, native collector build and harmless guest lifecycle also passed.
The rebuilt packaged core and advanced self-tests pass with a local
[Windows-unwind emulator build](../native/emulator/README.md) and CFG enabled.
Four frozen emulator regression cases passed. No real
malware was executed; old installers do not contain this source revision.

| User path | Implemented connection | External inputs |
| --- | --- | --- |
| File/folder scanning | Picker → isolated scanner → signatures/PE analysis → results/history | Core dependencies; optional full hash feed |
| Decoded/embedded content | Extraction/normalization → existing signature matching → detection retaining original identity | Additional analysis; oletools for VBA |
| Response | Detection → fresh scan with the same options → identity checks → encrypted quarantine → no-overwrite restore | Permissions and a reproducible signature detection |
| Model analysis | Training CLI → signed artifact → publisher pin UI → import → inference → evidence | Independently labelled data and actual trained weights |
| Reputation | Signed feed → pin/import → file/URL and attributed DNS evidence | Curated reputation entries and provenance |
| Updates | Configured HTTPS URLs → opt-in checks → signature/expiry/revision verification → atomic activation → worker refresh | Trusted publisher and hosted artifacts |
| Emulation | PE/import/delay-import mapping → TLS callbacks → bounded CPU/Win32 model → inspect changed memory and virtual files | Unicorn and supported x86/x64 semantics |
| Live monitoring | Configured sources → file inspection/behavior correlation → alerts/history → response | Optional Sysmon/network/native telemetry |
| Attributed writes | Native build/stage → protected collector selection → verified PID/start time → scoped write/canary correlation | .NET/TraceEvent and ETW authorization |
| Process-tree response | Process Actions → expiring plan → explicit selection → fresh checks → child-first actions → per-process results | Same-account processes and individual detections |
| Service | Protected installation → administrative policy → LocalService monitor using shared options | Built package and Windows permissions |
| OS blocking | Reviewed hash-deny export → explicit audit/enforced submission → managed receipt/status/removal | ConfigCI/CiTool and administrator authorization |
| Safe lab | Generated fixtures → scanner/synthetic telemetry → separate evidence → cleanup | Core runtime |
| Offline guest job | Prepare/start kit → imported guest specimen SHA-256 → explicit confirmation → guest execution → bounded summary → registered-guest disposal/reset | Current kit, Sandbox, source controller and guest specimen |

## Structural corrections in this pass

- Decoded, macro, container and emulated content matching existing signatures now
  produces a detection. Manual response reuses the same inspection configuration.
  Inner-content hashes never authorize automatic action against an outer file.
- Content, documents, models and reputation are independently selected. Absent
  model weights do not prevent content-only analysis. Model/heuristic scores remain
  review evidence; they do not masquerade as signature matches.
- Publisher pins have explicit per-user add/remove actions. They do not change
  Windows trust or the protected service's administrative pins. Signed payloads
  undergo schema validation before activation; expiry is explicit.
- Process-tree planning/approval has a real UI, expiry and per-process failure
  reporting. Native collector selection reaches foreground/background monitoring.
- Frozen applications have a guest-only runtime mode. Kits declare the protocol;
  old kits are rejected before specimen execution. The host receives bounded
  numbers, never sample bytes or guest-generated commands.
- Runtime disposal failure is visible and prevents another execution until reset.
  Local simulations and guest jobs cannot run concurrently. Window close waits
  for the owned runtime controller to finish.
- The old disabled VM-setup placeholder is replaced with prepare/start actions.
  The guest controller currently requires the source workspace and its registered
  kit; builds without that dependency disable runtime controls explicitly.

## Supported limits

The emulator provides a Win32 subset, not arbitrary DLL implementations, PEB/TEB,
SEH/VEH, static TLS storage or multithreading. Unsupported semantics stop analysis
with an omission. Virtual effects never mutate host files/registry/network. Document
inspection is bounded extraction, not a browser or Office/PDF renderer. These are
declared format/engine limits, not dummy success implementations.

No model, feed, publisher key, compiler, Windows permission or VM readiness is
fabricated. Those are real external inputs. Optional features remain unavailable
until their inputs exist. Source inspection cannot guarantee absence of structural
bugs; actual validation remains deferred at the user's request.
