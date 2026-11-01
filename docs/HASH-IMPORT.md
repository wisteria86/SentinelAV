# Hash-only candidate import

Run `scripts/Download-Hashes.ps1` in the PowerShell session holding ABUSECH_AUTH_KEY,
or run `.venv/Scripts/python.exe -m tools.feeds.download_hashes`. If the environment variable
is absent, the Python script prompts for the key with hidden input. Do not put
the key in arguments, source files, screenshots, or chat.

The fixed endpoint is the recent.csv export documented at
https://bazaar.abuse.ch/export/ . It covers recent additions from the last 48
hours, not the complete collection. Provider access and fair-use terms apply.
No sample endpoint is called and no sample files are downloaded.

The importer refuses redirects, limits download size/time and record count,
validates SHA-256 records, deduplicates hashes while retaining distinct labels,
and saves a separate hash-feeds/malwarebazaar-recent-* directory. It contains
the CSV, signatures.candidate.json, and a credential-free manifest. A manifest
is written only after all output files are complete. No active signature file
is overwritten. Review the candidate and manifest before integrating it.

The importer uses standard HTTPS verification; this is not a vendor-signed
SentinelAV update package. Labels reflect the source's assessment. Import tests
use synthetic CSV fixtures; authenticated live access must be verified by the
user running the script with their own key. Network failures are deliberately
reported without exception text because URLs may contain the credential.

## Full CSV ZIP import

`python -m tools.feeds.import_hash_archive C:\path\to\full.csv.zip --activate` streams the
single full.csv member into versioned SQLite tables. It never extracts archive
paths and never executes content. The archive/member size, record count, field
sizes, hash syntax, ZIP CRC, and database integrity are checked. Memory usage is
bounded through batches and SQLite cache limits rather than a full hash dict.

Malformed CSV quoting in user-submitted filenames can occur in the export.
Entire malformed rows are skipped, never repaired by guessing columns. The
manifest reports skipped counts and physical line numbers. More than 1,000
such rows or a rate above 0.1% (one omission allowed for tiny fixtures) rejects
the import. Invalid SHA-256 or incompatible column structure rejects the import.

Each complete import has a candidate manifest, archive/database checksums,
source metadata, and deduplicated hash/label records. Activation atomically
replaces only active.json. A prior active manifest is retained when present;
old database files remain for existing readers and rollback. To roll back,
restore the previous active manifest using an atomic replacement, then restart
readers. The small signatures.json overlay is preserved and takes precedence
for overlapping hashes. Invalid active manifests/databases fail initialization
visibly rather than silently dropping full-feed coverage.

Reopen the source application after code changes. For background mode, use the
updated window to Stop Protection and Start Protection; Stop releases the old
helper and the next Start loads current code/data. Settings → Scanning shows
the feed metadata; live monitoring shows the actual loaded hash count.

Existing installers are not modified by importing into the source tree. A new
build embeds only the currently active manifest/database, not the archive or
historical database versions. Respect the provider's redistribution terms.
Checksums establish local consistency, not provider authenticity or independent
verification of malware labels. A hash miss is not evidence that a file is safe.
