# Real-sample bounded emulation — 2026-11-03

**Emulation produced no additional signature detections.** The existing WannaCry
YARA detection remained; the emulator itself produced no confirmed findings on
any sample. This backend is operational on the harmless integration fixtures,
but its Windows environment and API coverage are inadequate for this sample set.

All six SHA-256 identities matched the preceding static comparison. Exact-hash
signatures were disabled for outer and derived content. Identical YARA/content/
document settings were used, with emulation enabled only in the third pass.
No rule, hash, score or threshold was tuned to these results.

| Sample | Instructions observed | Modeled API calls | Changed virtual pages | Emulated signature finding | Main reported limitation |
| --- | ---: | ---: | ---: | --- | --- |
| WannaCry | 6 | 0 | 0 | None | CPU stopped; incomplete environment/path |
| Emotet | 4 | 0 | 0 | None | API model stopped; incomplete path |
| ZeusVM | 42 | 0 | 2 | None | CPU stopped; incomplete environment/path |
| Linux Mirai | 0 | 0 | 0 | None | Windows PE backend not applicable |
| WannaCry Plus | 21 | 0 | 0 | None | Partial Win32 environment; no signature finding |
| Zeus Gameover | 16 | 0 | 1 | None | API model stopped; incomplete path |

Modeled-call counts do not count unsupported dispatch attempts as successful API
execution. Changed pages prove virtual memory writes, not successful payload
unpacking. The diagnostic category `budget_or_path_incomplete` groups incomplete
paths with budget limits; it is not proof that a time/instruction limit was hit.

The emulator pass reported four previously missed Windows samples as
**unavailable/incomplete**, rather than clean. Mirai remained statically undetected
with Windows emulation not applicable. WannaCry remained **detected with omissions**
because of its existing signature; that is not a new emulator detection.

No alerts occurred on the control observations, but none qualified as a complete
clean emulator result: eighteen inspected observations were incomplete, and two
planned Notepad observations were unavailable. These are repeated runs of the
same ten planned controls, not twenty independent benign files. No emulator
false-positive rate or protection rate is established.

## Execution boundary and evidence

Only the verified offline guest decrypted the existing pinned sealed archives.
Unicorn interpreted guest instructions using bounded virtual memory and modeled
effects; sample executables were never launched by Windows. The native emulator
library is the local Windows-unwind build with CFG retained. Networking and
clipboard/device sharing were disabled and host input was mapped read-only.

Only fixed outcome flags, counters, omission categories and SHA-256 metadata
returned to the host. No memory image, sample bytes, virtual file content or
arbitrary guest strings were exported. After inspection the registered guest
was discarded; its replacement passed fresh kit, offline and harmless baseline
checks. No Windows protection policy was weakened.

Evidence snapshots:

- `artifacts/evaluations/real-emulation-comparison-20261103.json`
- `artifacts/evaluations/real-emulation-corpus-result-20261103.json`
- `artifacts/evaluations/real-emulation-additional-result-20261103.json`
- `artifacts/evaluations/real-emulation-reset-20261103.json`
- `artifacts/evaluations/real-emulation-tests.log` — 22 targeted regressions passed.

The guest application was rebuilt and its harmless packaged baseline passed.
The release installer was not published. The two additional samples had been
used in previous evaluations and are not a genuinely unseen holdout.

## Next implementation priority

Improve the virtual Windows startup environment and modeled API semantics, using
harmless fixtures to verify them before repeating these same hash-disabled
evaluations. Preserve explicit unsupported-path reporting. Longer execution
budgets alone do not resolve the observed unsupported dispatch and CPU faults.
These findings do not justify promoting weak heuristic review signals to
confirmed malware detections.
