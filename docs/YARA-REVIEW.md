# YARA source-review milestone

## Installed scope

The managed catalog rules/catalog.json pins ESET malware-ioc revision
59745502656e813f9f79fc8005243edbc04f9397. It contains four selected source subsets:

| Bundle | Public detections | Private helpers | Scope |
| --- | ---: | ---: | --- |
| RedLine panel | 4 | 0 | Multiple UI headers, prompts, status messages, or command/action strings in MZ-prefixed data. These target panel artifacts, not general RedLine client coverage. |
| InvisiMole | 3 | 1 | Selected loader, DNS-downloader, and RC2CL patterns with multiple indicators and file/blob gates. |
| TA410 | 2 | 0 | Tendyron dropper and X4 multiple-constant indicators. |
| IIS ISN | 1 | 1 | ISN-specific text combinations gated by the private native-IIS-module rule. |

The existing SentinelAV_Harmless_Demo is a separate demonstration rule. Private
helpers never produce standalone detections. The research rules are historical
investigation signatures, not a comprehensive or newly discovered threat feed.

## Source, licensing, and changes

Source: https://github.com/eset/malware-ioc . The upstream repository and retained
file headers specify BSD 2-Clause licensing. Each installed subset preserves
the original copyright, license, disclaimer, metadata, and selected rule bodies.
Only the set of rule blocks was reduced. The repository license is also shipped
under rules/licenses/ESET-BSD-2-Clause.txt, which is included in packaged builds.
The catalog records upstream/installed SHA-256, source path, pinned URL/revision,
selection, scope, and source-review date. No ESET endorsement is implied.
Installer upgrades preserve an existing active definition pointer and publisher
key configuration while updating the packaged rule content.

Rules based only on generic crypto/ETW patterns, compiler fingerprints, short
magic values, permissive metadata, or single generic strings were not selected.
Some other multi-pattern rules were also left out to keep this first set narrow.
Excluded candidates are not silently enabled. Source review and compilation do
not establish acceptable false-positive rates or real-world protection quality.

## Loading and failure behavior

The loader reads at most 64 source files, 256 KiB each and 2 MiB total. Managed
files must match their catalog hashes. Source is read into a fixed compile
snapshot; include directives are disabled. Namespaces are deterministic, compile
warnings are errors, and managed rule identifiers must agree with the catalog.
Each source is compiled independently as well as together to verify dependency
scope. No downloaded precompiled YARA blobs are loaded.

Additional trusted local .yar/.yara files may be placed in rules/local; they
are explicitly labeled local/unreviewed. They obey the same limits and warning
policy but have no managed source-review claim. There is no automatic rule
downloader or UI that accepts rule code from an update package in this milestone.

Invalid managed files or compilation errors stop new scanner initialization
visibly, rather than silently disabling those rules. If YARA itself is absent,
the existing optional-engine policy reports hash/EICAR-only coverage. Runtime
matches retain the five-second per-file timeout. A match error/timeout records
an omission while preserving independent hash/EICAR findings for that file.

Scan JSON and live detections retain rule name, namespace, file digest, source,
revision, license, description, demo status, and review scope. Settings → YARA
Rules validates in a background worker and exposes bundle details. Live monitoring
reports its loaded research-rule count. Restart monitoring after changes; its
existing compiled snapshot is not silently replaced.

## Verification and remaining limits

Regression tests compile the selected rules, enforce thresholds/private-helper
behavior, reject managed-file tampering/includes/warnings, and check that match
failures preserve hash detections. A positive integration fixture consists only
of an MZ marker and inert strings; it is not a valid executable or malware and
is never executed. UI checks cover source details, error/recovery, and closing.

Broader benign-corpus evaluation, live samples, and VM testing remain deferred
at the user's request. No detection rate or false-positive rate is claimed.
Parser isolation, a protected service, and authenticated rule distribution are
future work. Catalog hashes do not resist a same-user attacker who can modify
both the source and catalog. Compilation is not isolated in another process;
trusted local rule authors must avoid resource-intensive constructs.
