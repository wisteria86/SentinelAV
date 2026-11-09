# Critical evaluation validation — 2026-11-04

## Measured results

- Final source unit suite: **262 passed**, including 32 critical-harness checks.
  Local transcript: `artifacts/critical-full-unit.log`.
- Launcher: offscreen Qt profile/completion/report-button check passed; screenshot
  at `artifacts/screenshots/critical-harness.png`.
- Python compilation and parsing of the modified lab PowerShell scripts passed.
- Native ETW collector built on F:; dependency-only `--self-check` passed without
  starting host ETW collection. Guest event delivery has not been established.
- Application and installer 0.16.0 built on F:. Packaged harmless self-test passed
  all 15 checks, including quarantine/restore and audit records. This does not
  measure malware protection. Current-source build attestation was recorded.
- Critical host-only run completed **47 cases: 2 passed, 45 blocked**.
  [Run report](../logs/2026-11-04_20-46-44-6f297b41d876/report.md).

The safe run performed feature inference and metadata/scorer checks only. It
launched no guest or malware and changed no host security settings.

## Detection evidence

The previously examined 4,000-row .NET feature regression reproduced:

| Measure | Result |
| --- | --- |
| Malicious feature examples flagged | 1,783 / 2,000 (89.15%) |
| Malicious feature examples missed | 217 |
| Benign feature examples flagged | 4 / 2,000 (0.20%) |
| One-sided 95% false-positive upper bound | 0.4571% |

These are model review flags on feature records, not confirmed detections of
executed specimens. No threshold or model was activated or tuned. The regression
case passes its **benchmark completed** assertion; it does not pass the release
detection targets. `feature-misses.jsonl` and `feature-false-alarms.jsonl` retain
case-linked identities and individual model scores for investigation.

## Deliberate failure checks

Tests reject missing/lost evidence, mixed versions, uncorroborated confirmations,
duplicate cases/specimens, contaminated signature-free modes, forged pass results,
small cohorts, impossible counts, malformed/trailing/oversized compressed exports,
missing or escaping evidence references, unrelated guests and protected fixture
resources. A dedicated check verifies unavailable selected PE inspections remain
in the raw-detection denominator: 150/200 is 75%, never 100%.

## Remaining qualification blockers and implementation limits

At this run, C: had approximately 3 GiB free, below the frozen 10 GiB reserve.
No dedicated VM configuration or reviewed Sysmon/ETW support manifest existed.
Independent temporal/family-disjoint inventories, the 200-specimen/20-family
qualification corpus and 30,000 independent automatic-action controls were absent.
The eight existing specimens remain regression material.

The implemented guest adapters, reset/disposal, telemetry probes, recurrence,
installation, response and long-run paths still require actual guest integration
validation. A unit pass cannot establish their operational correctness.

Physical sleep/resume and the full application-performance matrix remain
incomplete. The current performance case measures a fixed file workload and stays
partial; the recovery case explicitly reports its sleep/resume omission. Live
fixtures without independent harmful-outcome ground truth remain inconclusive.
Seeded remediation fixtures are scoped templates; they do not independently prove
cleanup of a naturally established infection. Guest evidence is not externally
attested. No Defender comparison or superiority claim has been established.

**What's next:** investigate the 217 feature misses and four false alarms without
tuning on final holdouts; supply the documented environment/corpus prerequisites,
complete the explicit workload gaps, and run the guest qualification tracks.
