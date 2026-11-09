# Definition update milestone

## Using the application

Settings → Definitions provides background operations for recent CSV merges,
full CSV ZIP imports, signed packages, reviewed corrections, and rollback. The
page shows the active full-feed record count, import age, operation provenance,
and whether a publisher trust key is configured. Imports older than 48 hours
are labeled stale. This is import age, not proof of current threat coverage.

New scans use the activated snapshot. Running monitors retain their original
snapshot until explicitly stopped/restarted. Operations use a common writer
lock; concurrent writers fail visibly. Closing during an operation waits
asynchronously for completion, or requests cancellation of a long full import.
No sample acquisition, execution, automatic quarantine, or VM work is involved.

## Recent additions and corrections

`python -m tools.feeds.download_hashes --apply` downloads the fixed MalwareBazaar recent.csv
endpoint with the key supplied through ABUSECH_AUTH_KEY or a hidden prompt. It
saves a validated candidate, then merges it into the existing full SQLite feed.
The key is not saved, placed in command arguments, or logged. This is a manual
command; no recurring downloader or stored credential is configured.

Alternatively: `python -m tools.feeds.manage_definitions recent C:\path\to\recent.csv`.
Missing hashes in a recent export are never treated as removals. Existing hashes
in that export get the newly supplied source labels; other hashes stay intact.
Explicitly revoked hashes are not resurrected by ordinary recent imports.

Reviewed correction JSON has exactly these two arrays:

```json
{
  "upserts": [
    {"sha256": "<64 lowercase hex characters>", "labels": ["Reviewed label"]}
  ],
  "removals": ["<different 64 lowercase hex characters>"]
}
```

Use `python -m tools.feeds.manage_definitions corrections C:\path\to\corrections.json`.
These local files are explicitly manual and not publisher-authenticated. A
removal suppresses matching old MalwareBazaar JSON overlay entries as well as
the database entry. Independent local overrides and user-approved trusted-file
exceptions remain separate policies. Full reimports retain explicit revocations.
An explicit correction upsert or a valid signed package can restore a revoked
hash. Corrections affect hash detection only; YARA may independently detect it.

### Reviewed Zeus additions, 2026-11-02

Two previously missed, guest-verified research specimens were added through the
existing explicit-corrections path. The active snapshot grew from 1,164,910 to
1,164,912 hashes. The payload and its source/identity notes are shipped under
resources/reviewed-hashes/zeus-20261102.changes.json and the adjacent provenance
JSON. Both archives were pinned to theZoo revision
48515e492013bc5bb2769249ea539436bb3e733f; decoded bytes and their SHA-256 were
verified only inside the offline guest. Family labels come from that repository,
not independent vendor consensus or a signed publisher update.

These entries are explicitly labeled locally reviewed research samples. SQLite
lookup now uses the neutral prefix "Hash database:" instead of attributing all
manual corrections to MalwareBazaar. The original JSON overlay provider labels
remain intact. The base CSV/source metadata still describes the old full import;
a two-entry manual update is not a new comprehensive MalwareBazaar download.

Old snapshots remain available for the normal rollback operation. A source clone
without the ignored full database must first import a base feed, then can apply
the supplied correction JSON using the command above. Packaged lab builds contain
the current database plus the human-readable correction/provenance files.

The old ZeusVM and Gameover misses remain preserved in their original evaluation
records. After curation these exact files are regression cases, not untouched
holdouts. Their new hash matches do not demonstrate coverage of modified variants.
No malware is executed to apply a definition update.

## Signed packages

The default trusted-update-keys.json contains no keys. No online update publisher
or server is configured. The application rejects all signed packages until a
publisher public key is provisioned through a trusted installation process.
It never trusts a key supplied by an update package. Private keys are not stored
in the app; tests generate ephemeral fixture keys only.

Supported ZIPs contain exactly manifest.json, changes.json, signature.ed25519.
There is no archive extraction. The Ed25519 signature covers the exact manifest
bytes. The manifest binds the payload SHA-256 and current base database SHA-256,
stable channel, pinned key ID, positive monotonic revision, issue time, and
expiry. Validity cannot exceed 14 days; future-dated and expired packages fail.
The changes JSON uses the correction schema above. Duplicate JSON fields,
oversized payloads, ambiguous archive members, unknown keys, invalid signatures,
wrong bases, replays, and revision downgrades are rejected before activation.

Manifest fields: format=1, channel="stable", key_id, revision, issued_utc,
expires_utc, base_database_sha256, changes_sha256. Times are timezone-aware ISO
8601 strings. Payload/manifest limits are 32 MiB/16 KiB. At most 100,000 upserts
and 100,000 explicit removals are accepted per package; label counts are bounded.

## Activation, rollback, and limits

Every update copies the current snapshot, validates changes, checks SQLite
integrity, hashes the result, and atomically switches active.json. Old files
remain intact for readers and rollback. A failed activation does not replace
the active pointer. `python -m tools.feeds.manage_definitions rollback` restores the previous
snapshot after checksum validation. It retains that snapshot's definition age
and the highest accepted signed revision, preventing replay after a deliberate
rollback. Full manual reimports also preserve this revision high-water mark.
Historical snapshots are not automatically pruned in this milestone; each
update uses additional disk space. Retention management remains deployment work.

These protections do not provide tamper resistance against the same Windows
user or an administrator who can edit the installation, trust store, or
manifests. Code signing, protected service-owned storage, publisher key rotation,
an operated release-signing pipeline, remote hosting, scheduled fetching, and
freshness guarantees from the provider remain separate deployment work.

Checksums establish consistency, not malware-label accuracy. Update regression
checks use generated hash-only fixtures and ephemeral signing keys. Separate
bounded guest static-sample evaluations are documented in STATIC-EVALUATION.md;
they do not execute samples or establish broad protection effectiveness.
