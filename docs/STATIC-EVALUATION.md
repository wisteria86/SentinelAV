# Static detection evaluation

This evaluates file contents against SentinelAV's active hashes and YARA rules.
It never launches a sample, extracts archive members to disk, invokes a sample
installer, quarantines files, or changes antivirus settings. ZIP members may be
inspected in memory under the existing engine limits. AMSI consumer inspection
is disabled here to keep this measurement specific to SentinelAV's own static
detection. It does not measure behavioral protection.

## Input and reports

Use an explicit manifest, with at most 64 files, each at most 8 MiB:

```json
{"schema":1,"files":[{"path":"sample.bin","sha256":"LOWERCASE_64_CHARACTER_SHA256","label":"malware","provenance":"Repository revision, original archive digest, sample identity and review reference"}]}
```

Allowed labels: malware, benign, test, unknown. These are declarations requiring
review, not independently established ground truth. Relative paths cannot escape
the corpus or refer to linked paths. Duplicate names and hash mismatches fail.
Malware/unknown labels require an offline Windows Sandbox guest identity.
Relabeling malware as a test or benign fixture does not establish safety.

From the source tree, for known harmless fixtures:

    .\.venv\Scripts\python.exe -m tools.evaluation.evaluate_corpus C:\corpus\manifest.json --output C:\new-report-directory

Inside a prepared guest, using a bundle containing this evaluation mode:

    C:\SentinelAV-Test\App\SentinelAV.exe --evaluate-corpus C:\guest-corpus\manifest.json --evaluation-output C:\guest-report

The report directory must be new and separate from the corpus. JSON and escaped
HTML reports include original labels, pinned file hashes, per-file findings,
definition metadata, YARA source hashes/versions, errors and timing. Exit code 0
means complete coverage; 2 means review omissions. Invalid inputs fail instead
of producing a clean verdict. No sample contents are included in HTML.

Each file is fingerprinted before and after its bounded worker scan. The worker
has existing job memory/process limits and a per-file scan timeout. Initialization
is separately bounded. New files are not started after the 10-minute run budget;
the current operation may finish after that budget. A worker is closed between
files. These controls provide fault/resource isolation; they do not remove the
worker's account privileges or turn it into an AppContainer.

Outcomes are detected, not_detected, detected_incomplete, unavailable. Omitted,
changed, unreadable, oversized, timed-out, or parser-failed samples are never
counted as clean. Missing YARA compilation also means incomplete coverage. No
percentage protection claim is generated from this small, caller-selected set.

## Containment review — 2026-11-02

| Boundary | Evidence / decision |
| --- | --- |
| Hypervisor isolation | Actual Windows Sandbox guest startup and reset verified. |
| Network | Disabled in pinned profile; guest has no active network adapter. |
| Host files | Only staged app input is mapped, read-only; inert write denied. No writable results mapping. |
| Clipboard/devices/GPU | Disabled in pinned profile; runtime clipboard transfer was not tested. |
| Reset | A guest-local marker disappeared after discarding the registered guest. |
| Scan workers | Resource/fault limits only; guest account privileges remain. |
| Evidence | Guest-local JSON/screenshots; fixed checks return status through official Sandbox CLI. |
| Real sample acquisition | The subsequent pinned pilot uses in-memory archive verification, AES-GCM host storage, a separate DPAPI-protected transfer key and guest-only unpacking. See the pilot result below. |

Initial decision: a narrowly scoped **static-only real-sample pilot** requires
a pinned repository revision, archive hash, sample hash and a guest-local-only
unpacking procedure. The pilot below now implements those requirements. Do not clone a
whole malware collection onto this host or unpack samples into host shares.
Keep host antivirus enabled; if it blocks acquisition, record the limitation
rather than adding exclusions. The runner alone is not permission or a safety
guarantee for arbitrary content.

Dynamic execution is outside this review: persistence, propagation, credential
theft and network behavior have not been contained or evaluated. No arbitrary
execution runner, network enabling, antivirus disabling or sample installation
is implemented here. A dedicated disposable VM remains the proposed environment
for a later execution milestone; this review does not require purchasing an OS
license or signing certificate.

Microsoft documents both the isolation controls and the risks from exposed host
folders in [Windows Sandbox configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).
Disabling networking/shares reduces exposure; it is not proof that guest escape
is impossible. The static/dynamic distinction here is our scope decision.

## First real-sample pilot — 2026-11-02

One historical Ransomware.WannaCry sample from ytisf/theZoo was statically scanned
inside the offline guest. Repository revision:
48515e492013bc5bb2769249ea539436bb3e733f. The archive's pinned Git blob is
4a7b532e7fc6d51033a0e97e7cf1f4192528d686 and its SHA-256 is
707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a.
The decoded sample matched the published SHA-256:
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.

Result: **detected_incomplete**. Exact SHA-256 matching detected it; YARA did
not match. Encrypted ZIP members embedded in the sample were omitted, so the
result is explicitly incomplete rather than claiming full content inspection.
The post-scan sample digest was unchanged. This is evidence for one historical
sample only, not a malware detection rate or proof of behavioral protection.

The host acquisition tool reads the bounded encrypted repository ZIP in memory,
verifies the pinned Git blob and encrypted ZIP metadata, and writes only a new
AES-256-GCM envelope. Its random transfer key is stored separately under Windows
CurrentUser DPAPI. Neither raw ZIP bytes nor unpacked malware are explicitly
written to the host filesystem. This is an application storage property, not
a claim against operating-system paging or memory inspection.

Prepare-TestEnvironment.ps1 -SealedStaticPilot maps only the ciphertext in the
existing read-only kit, never the key file. Invoke-StaticPilot.ps1 unlocks the
transfer key in host memory and passes it to SentinelAV through the fixed guest
command. The key is transiently present in process arguments; it is a transfer
key for a public research archive, not a credential or production-secret channel.

The guest checks identity, kit and offline state, authenticates the envelope,
verifies the pinned archive again, bounds member count/expanded bytes, and reads
members in memory. Archive names are ignored. Only the exact SHA-256-matched
sample is written under a new guest-local directory as sample.bin. Its contents
are passed to the static evaluator; no loader, shell, installer or sample process
is invoked. Antivirus settings are not changed. The import mode is restricted
to this pinned sample, not a general malware execution mechanism.

The full JSON/HTML report stays guest-local until disposal. A fixed status enum
exports only verdict, hash/YARA finding flags, coverage and unchanged-file flags
to the host; coverage error categories are also fixed, not sample-derived code.
The retained host summary is artifacts/lab/windows-sandbox/static-pilot-result.json.
The guest containing the unpacked sample is discarded after review. Ciphertext
and its DPAPI-protected transfer key remain as local ignored lab artifacts.

An initial command that would have written the repository ZIP directly was
rejected by automatic approval review because encryption had not been verified
before host storage. It did not run. The subsequent AES-GCM-only storage method
was reviewed and allowed; no Windows protection bypass or exclusion was used.

## Repeatable verification

### Four-family expansion

The follow-up plan selects one explicit member from each of WannaCry, Emotet,
ZeusVM and Linux.Mirai.B at the same pinned repository revision, before running
any new detection queries. Specs, archive sizes, Git blob identities, published
checksums and member checksums are fixed in lab/static_corpus.py. New archive
checksum files describe the ZIP, while WannaCry's checksum describes its member;
the importer records the scope actually verified rather than assuming they are
the same. For Emotet/ZeusVM, legacy member-name SHA-1/MD5 checks supplement the
pinned archive and its SHA-256; the decoded SHA-256 is computed in the guest.

ZeusVM's companion JPG and three other Mirai archive members are outside this
selected four-file corpus. They are not silently counted as scanned, benign,
or detected. This test is static file recognition across historical families;
the Linux sample does not measure Windows runtime protection. An initial
metadata guard rejected the multi-member layouts before any guest unpacking;
selection was made explicit from metadata, still before detection results.

The ten comparison candidates are cmd.exe, whoami.exe, notepad.exe, kernel32.dll,
user32.dll, advapi32.dll, crypt32.dll, ntdll.dll, gdi32.dll and Windows PowerShell
from the fresh guest's System32 directory. The controller requires a Valid
Microsoft Authenticode signature and stable SHA-256 across signature validation.
The importer checks the fingerprint again before copying each selected file.
These are signed guest-image controls, not independently proven harmless files.
Unverified or missing candidates are reported unavailable, never clean.

acquire_corpus.py keeps every downloaded archive in memory until pinned identity
and encrypted-member metadata checks pass, then writes only AES-GCM ciphertext.
Prepare-TestEnvironment.ps1 -SealedStaticCorpus maps those four envelopes read-only
and omits the DPAPI transfer key. Invoke-StaticCorpus.ps1 supplies the transfer key
in memory, verifies clean-control provenance and runs SentinelAV's static-only
mode. The guest report retains all scanned-file hashes, YARA evidence, definition
versions, errors and timing. The host receives fixed verdict flags and the two
previously unknown sample digests through bounded metadata queries, never file
contents. The host summary is static-corpus-result.json under the lab artifacts.

All four requested malware files and ten requested controls remain in the host
summary denominator even if import/provenance checks fail. Such cases are
unavailable, not misses or successful scans. Benign detections require review
and are not automatically called confirmed false positives. No representative
detection percentage is claimed and no signatures/rules are tuned to this set.
The guest containing unpacked files is discarded after evidence review.

Observed results (same frozen definitions/rules; no tuning to these samples):

| Selected sample | Exact hash | YARA | Overall outcome |
| --- | --- | --- | --- |
| WannaCry | Detected | No match | Detected with encrypted embedded-member omissions |
| Emotet | Detected | No match | Detected, complete within configured limits |
| ZeusVM | No match | No match | Not detected, complete within configured limits |
| Linux Mirai | Detected | No match | Detected, complete within configured limits |

All four sample fingerprints were unchanged after scanning. Nine Microsoft-signed
Windows controls were inspected with no detections. The tenth selected candidate,
System32 notepad.exe, was absent from this guest image and remains unavailable in
the denominator. The nine inspected control hashes were retained after verifying
that guest report hashes exactly matched their host system-file counterparts;
the malware contents were never opened on the host. Zero findings in nine controls
does not establish a general false-positive rate.

All 109 source unit tests passed. No sample was executed. The ZeusVM miss is
retained as a miss: no hash entry or sample-specific rule was added to make this
evaluation pass. The next detection improvement should be validated on separately
selected holdout samples, keeping this set as regression evidence.

The updated packaged --self-test generates five inert fixtures: an ordinary
document, renamed marker, UTF-16 marker, nested ZIP marker, and unsupported 7z
header. Expected results are one not_detected, three detected and one unavailable.
The unavailable result deliberately checks that missing coverage is visible.
Guest self-test evidence is C:\SentinelAV-Test\SelfTest\corpus-evaluation.json.

The source unit tests cover manifest traversal/duplicates, host refusal for
unknown samples before fingerprinting, hash mismatch, partial results and
HTML escaping, plus a real harmless worker scan. These tests do not establish
real-malware efficacy.
