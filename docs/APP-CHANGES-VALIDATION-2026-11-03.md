# App Changes validation — 2026-11-03

- Unit regression suite: **192 tests passed**. Tests cover encrypted history,
  pre-existing versus observed state, incomplete inventories, exact referenced
  file linkage, approval conflicts, recovery rescanning, export privacy,
  task-versus-trigger enablement and post-action persistence reconciliation.
- Desktop regression checks: **all 12 scripts passed**, including App Changes,
  existing page navigation, background monitoring after GUI closure, quarantine,
  definition updates, scheduling and harmless lab simulations. The App Changes
  page was also checked again after its final receipt/export controls.
- Real file-recovery integration: **passed**. A temporary INI configuration was
  restored byte-for-byte using the actual DPAPI journal, isolated scanner and
  exclusive Windows handles; the separate control file was unchanged. No host
  registry, task or service settings were changed by that check.
- Read-only Windows inventory: **366 resources**, all five supported classes
  completed without an inventory error on this account at the observed time.
- Final frozen executable self-test: **PASS**, including modeled Win32 API
  dispatch, normalized-content detection, 1,164,912 hash signatures, scanner
  worker isolation, DPAPI, Qt response controls and harmless lab profiles.

Frozen self-test evidence:

`F:\SentinelAV-Work\evaluations\product-selftest-37cf5a06e8ef4993bab0f79bcd2697ff\run\self-test.json`

Source unit log: `artifacts/current-unit-tests.log`.

Real configuration recovery check:
`tests/integration/check_recorded_recovery.py`.

These are functional checks. They do not establish malware detection efficacy,
complete task/service repair, reboot recurrence protection, a 30,000-benign
automatic-action gate, or a Defender advantage. The .NET feature-model pilot
failed its detection release gate and was left inactive. See
[implementation and remaining work](APP-CHANGES-AND-INDEPENDENT-PROTECTION.md).
