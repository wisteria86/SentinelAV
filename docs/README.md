# Documentation

| Read this | For |
| --- | --- |
| [Final deliverables](deliverables/) | How to run SentinelAV, the architecture document and the security analysis |
| [Evaluation report, 9 November 2026](EVALUATION-2026-11-09.md) | Measured detection and false-positive rates, misses, disclosures and limits |
| [How SentinelAV detects threats](DETECTION.md) | Scoring, file types, scan modes, real-time protection, removal and limits |
| [Critical product evaluation](CRITICAL-EVALUATION.md) | One-click profiles, evidence scoring, telemetry, Sandbox/Hyper-V prerequisites and qualification gates |
| [Installed learned detection](LEARNED-DETECTION.md) | Active boosting ensemble, raw-byte neural classifier and measured limits |
| [Strict signature-free evaluation](SIGNATURE-FREE-EVALUATION.md) | Disabled detection channels, batching, readiness blockers and measurement limits |
| [Protected machine remediation](PROTECTED-REMEDIATION.md) | LocalService history, one-shot UAC broker and native test scope |
| [App Changes and independent protection](APP-CHANGES-AND-INDEPENDENT-PROTECTION.md) | New tracking/cleanup code, measured ML results and explicit remaining implementation |
| [Project structure](PROJECT-STRUCTURE.md) | Folder map and order for reading the code |
| [AMSI provider](AMSI-PROVIDER.md) | Native implementation, local tests, deployment gates |
| [AMSI without purchases](AMSI-ZERO-COST-OPTIONS.md) | Existing Windows policy, free signing options, and unresolved deployment checks |
| [Guest AMSI validation](GUEST-AMSI-VALIDATION.md) | Reset, LocalService, real AMSI/PowerShell checks, and cleanup evidence |
| [Test environment](TEST-ENVIRONMENT.md) | Offline Windows Sandbox kit, activation, launch, and guest checks |
| [Static evaluation](STATIC-EVALUATION.md) | Manifest runner, report outcomes, containment review and real-sample prerequisites |
| [Algorithmic analysis](ALGORITHMIC-ANALYSIS.md) | General static features, independent data splits and offline anomaly calibration |
| [Learned detection](LEARNED-DETECTION.md) | Installed EMBER2024 ensemble and MalConv2 classifiers, calibration and limits |
| [Defense implementation](DEFENSE-IMPLEMENTATION.md) | Implemented protections, unfinished work, and deployment prerequisites |
| [Feature guide](FEATURES.md) | Application behavior, configuration, and verification commands |
| [Background engine](BACKGROUND-ENGINE.md) | Monitoring while the GUI is closed and IPC boundaries |
| [Hash imports](HASH-IMPORT.md) | Recent/full hash-feed import and validation |
| [Definition updates](DEFINITION-UPDATES.md) | Corrections, signed updates, rollback, and publisher trust |
| [YARA review](YARA-REVIEW.md) | Rule provenance, licenses, scope, and checks |
| [Hardening](HARDENING.md) | Security boundaries and remaining limitations |
| [Defender method gaps](DEFENDER-GAP-ANALYSIS.md) | Method-by-method comparison, PE capabilities, Sysmon sequences and deployment limits |
| [Release notes](RELEASE-NOTES.txt) | Version history |

Run commands from the project root, which contains `app.py`, rather than from
this documentation folder. The original proposal is in `references/`.
