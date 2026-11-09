# Advanced analysis and safe behavioral evaluation

## Advanced benign-file inspection

Content and document analysis inspected the same 488 files before and after a
warning-classification fix: 150 System32, 150 SysWOW64, 38 Python DLLs and 150
Qt files. Hash inventory and postchecks matched. Emulation, AMSI, trained-model
and reputation analysis were disabled; these are not results for those layers.

Final observations:

- No signature or derived-content detections, and no skipped files.
- One file had a capability review signal in both structural and advanced views:
  `AppVEntSubsystemController.dll` imports APIs that combine remote memory writes
  and thread creation. These capabilities can be legitimate. This is one reviewed
  file, not two detections or a confirmed false positive. No allowlist was added.
- Nine Qt binaries exceeded the import-name budget. Their inspection remains
  incomplete and the report remains **Incomplete / review omissions**.
- Four irrelevant active-document size warnings disappeared after the fix.
  Executables that are neither HTML/RTF by content nor HTML by extension no
  longer enter that parser's size gate. Actual oversized HTML/RTF inputs still
  report their size limit. No parser limit was increased.
- Final scan: 26.2566 seconds, sampled peak RSS 87.70 MiB. Labels remain presumed
  benign; this is not an independently established false-positive rate.

Evidence before the fix:
`artifacts/evaluations/benign-20261103T145621Z-6387024d/report.json`

Final JSON and HTML:
`artifacts/evaluations/benign-20261103T145807Z-c6ad210b/report.json`

## Safe behavior checks

All four existing simulation profiles passed: marker scanning, generated benign
documents, canary/burst correlation and synthetic network indicators. All six
additional controls passed: repeated writes to one file, bulk writes without
corroboration, exclusions, ordinary process metadata, Office/encoded-command
correlation and an unchanged canary. Temporary run folders were disposed.

Process/network records were injected; no test process was launched and no
network connection was made. Synthetic records prove scoring behavior, not live
process/network collection. Canary edits used only generated harmless text.

The first harness expectation incorrectly omitted the intermediate warning
before a correlated alert. The engine correctly emits `Warning`, then `Alert`
as evidence accumulates. The expectation was corrected; scoring was unchanged.
The initial failed report is retained at
`artifacts/evaluations/behavior-20261103T145632Z-4d6ca6ad/report.json`.

Final simulation/control evidence:
`artifacts/evaluations/behavior-20261103T145739Z-1437d23a/report.json`

Separately, the live Qt integration passed with the actual filesystem monitor:
canary creation/change → warning → generated file burst → combined-risk alert →
persisted events and visible alert banner → stop monitoring. Stopping canary
tracking left the canary intact until the temporary fixture directory cleaned up.
Log: `artifacts/evaluations/behavior-live-ui.log`.

Twenty-six targeted unit/regression tests passed. An initial restricted test
attempt could not access its sandbox-provided temp directory; the successful
run used the project's usual writable temporary fixture location. No test
failure was hidden or fixed by weakening a protection setting.

## Repeat

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_benign --advanced --limit 500 --per-root-limit 150 --repeats 1 --timeout 600 --root C:/Windows/System32 --root C:/Windows/SysWOW64 --root C:/Users/pc/AppData/Local/Programs/Python/Python312/DLLs --root .venv/Lib/site-packages/PySide6
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_behavior
.\.venv\Scripts\python.exe -m tests.ui.verify_behavior_ui
```

These runs establish selected inspection, scoring, filesystem collection and UI
paths. They do not establish ransomware prevention, live process/network
attribution, or effectiveness against a representative malware population.
The existing release installer was not rebuilt. Next: retain usable partial
import evidence when large binaries reach a parser budget, without presenting
bounded inspection as complete.
