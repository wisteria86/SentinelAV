# YARA source-review milestone

## Installed scope

The current source catalog is 2026.11.02.3: 15 research rules, two private helpers,
one demo and ten source files. The dated sections below retain the original
scope and subsequent measured results rather than rewriting historical tests.

The original managed catalog rules/catalog.json pins ESET malware-ioc revision
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

### Expansion reviewed 2026-11-02

Catalog version 2026.11.02.2 adds three public research rules, bringing the total
to 13 research detections, two private helpers and one harmless demo across eight
source files. No exact-hash entry was added for the missed ZeusVM sample.

| Added rule | Source snapshot | Review/adaptation |
| --- | --- | --- |
| Win32_Ransomware_WannaCry | ReversingLabs e0a0be54aa1e11ccfd6854e4f19e9476f328fd84 | MZ, entry-point code and long function patterns; unchanged rule body. |
| Win32_Trojan_Emotet | Same ReversingLabs revision | Resource-decryption patterns paired with filename/state-machine/decompression patterns. Parentheses now apply the original MZ gate to every OR branch. No pattern bytes changed. |
| win_vmzeus_auto | Malpedia downloaded rule version 20260917, rule hash 53a643781c18e08f4a50949af60172d837a0b6f6 | Original seven-of-ten threshold and size cap retained; MZ and PE-signature gates added. The instruction sequences overlap, so seven matches do not mean seven independent behaviors. |

The ReversingLabs rules carry the retained MIT notice in
licenses/ReversingLabs-MIT.txt. The VMZeus derivative retains author Felix
Bilstein, Malpedia/yara-signator metadata and the generation disclaimer, is
distributed under CC-BY-SA-4.0, and includes the full license in
licenses/CC-BY-SA-4.0.txt. Adaptation comments and catalog fields identify changes.
These notices cover the third-party rule components; no top-level project
license was selected by this change.

Malpedia's live download returned a ZIP containing the text rule; only the exact
bounded rule member was read. The downloaded September snapshot differs from
an older cached web page. The installed/upstream SHA-256 values pin the actual
reviewed text. Its source_revision is Malpedia's rule identifier, not a Git
commit. A future download from the same URL must not silently replace it.

The source warns that generated signatures use memory/unpacked samples and may
generalize poorly. Header checks narrow file matches but do not solve packing,
virtualization or encrypted payload inspection. Tests remain static only.

Verification includes 110 unit tests, ten Qt UI scripts, and two scans each of
500 presumed-benign System32 and 500 SysWOW64 files. No detections were seen;
the SysWOW64 corpus retains one unsupported legacy NE-format compobj.dll
metadata omission. These are selected local files, not a certified goodware
corpus or proof of a general false-positive rate. Guest regression and separately
selected holdout results are retained under artifacts/lab/windows-sandbox.

The holdouts are one WannaCry_Plus archive member and the original packed
eqig.ex_ member of ZeusGameover_Feb2014 at the previously pinned Zoo revision.
They were selected before verdicts; auxiliary/unpacked Gameover members were
not substituted. These files were unused in this project's earlier evaluations,
but upstream rule-development overlap is unknown: they are not a statistically
independent or representative unseen test set. No sample is executed.

Observed guest results: the original WannaCry sample gained the ReversingLabs
YARA match while retaining its exact-hash detection and encrypted embedded-member
omissions. Emotet and Mirai stayed hash-only detections. ZeusVM stayed a miss;
its exact hash is absent from the active index and the published VMZeus pattern
threshold does not match this on-disk specimen. Its recorded header is PE32.
A narrow section-name check found no UPX/ASPack/MPRESS/VMP/Themida marker; this
does not establish whether the specimen is packed or virtualized. No unpacking
or execution was attempted and no sample-specific rule was invented.

The separately selected WannaCry_Plus member was detected by hash only, with
complete coverage within configured limits. The selected original Gameover
member was not detected. These misses remain in the retained report. Each guest
run again inspected nine validly Microsoft-signed controls with no detections;
Notepad remained absent/unavailable. Source benign-file scans saw zero findings
across 1,000 selected paths (500 per architecture directory), with the noted
legacy NE metadata omission retained. Neither count measures broad AV efficacy.

Host evidence: yara-expansion-validation.json, static-corpus-baseline.json,
static-corpus-result.json and static-holdout-result.json under the lab artifacts.
The release installer was not replaced by this lab/source update. New scans
load the new rule snapshot; an already-running monitor must be restarted to
refresh its compiled snapshot.

Sources: [ReversingLabs repository and license](https://github.com/reversinglabs/reversinglabs-yara-rules/tree/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84),
[Malpedia VMZeus](https://malpedia.caad.fkie.fraunhofer.de/details/win.vmzeus),
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

### Further Zeus-family review, 2026-11-02

Adds win_gameover_p2p_auto and win_zeus_auto from the downloaded Malpedia
20260917 snapshot, retaining CC-BY-SA-4.0 attribution/disclaimers and recording
upstream/installed SHA-256. Both preserve original pattern bytes, seven-of
thresholds and size caps (598,016 and 319,488 bytes respectively), with added
MZ/PE signature gates. They are family-specific generated patterns, not generic
Zeus coverage or a replacement for examining packed/encrypted content.

The two already-measured missed hashes were separately curated as local reviewed
definitions; see DEFINITION-UPDATES.md. Subsequent detection of those exact bytes
must be reported as a regression check, not fresh independent detection evidence.
The fresh project-level validation selects the original encrypted archive member
invoice_2318362983713_823931342io.pdf.exe from ZeusBankingVersion_26Nov2013 and
output.1301364.old from ZeusGameover_Feb2014 before scanning. Neither member was
previously decoded/tested here. The latter shares an archive with the earlier
Gameover specimen, so it is not an independent family/source distribution.
Upstream rule-development overlap is unknown.

Acquisition remains authenticated-ciphertext-only on the host; decoded filenames
are fixed inert .bin paths inside the offline guest. No unpacked companion
members are substituted and no sample is launched.

Measured outcome: both curated files (the earlier ZeusVM and Gameover misses)
now detect by their newly reviewed exact hashes. Neither gains a YARA match.
Both fresh specimens also remain undetected by hash and YARA, with unchanged
post-scan fingerprints and complete inspection within configured limits.
The new family rules therefore have no demonstrated positive match in this
selected on-disk corpus. They remain research signatures, not evidence that the
Zeus variant gap is solved. The fresh misses were not added to the hash update.

110 unit tests and ten Qt UI checks passed. Two scans each of the same 500
System32 and 500 SysWOW64 paths again produced no findings; the existing legacy
NE-format compobj.dll metadata omission remains. Nine validly Microsoft-signed
guest controls per run produced no detections, with Notepad absent/unavailable.
These repeated controls are not additional unique goodware samples.
The master record is artifacts/lab/windows-sandbox/zeus-coverage-validation.json.

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

Bounded benign-file evaluation and static guest sample tests have now run; see
the expansion notes and STATIC-EVALUATION.md. No representative detection rate
or false-positive rate is claimed. Parser workers and a guest-tested protected
service exist, but authenticated YARA distribution remains future work.
Catalog hashes do not resist a same-user attacker who can modify
both the source and catalog. Compilation is not isolated in another process;
trusted local rule authors must avoid resource-intensive constructs.
