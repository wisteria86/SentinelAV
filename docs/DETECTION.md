# How SentinelAV detects, explains and removes threats

SentinelAV never runs a file to judge it. Files are read, parsed and scored inside a
separate, memory-limited worker process. Emulation is a virtual CPU and stays off unless
you turn it on under Settings → Defense.

## How a file is scored

Every scanned file gets a score from 0 to 100, a verdict, a confidence level, and the
reasons behind them.

| Score | Verdict | What happens |
| --- | --- | --- |
| 70 and above | Malicious | Reported as a threat |
| 35 to 69 | Suspicious | Reported for you to review; never acted on automatically |
| Below 35 | Clean | Not reported. This does not prove a file is safe |

**Evidence layers**

| Layer | Examples | Effect |
| --- | --- | --- |
| Exact identity | SHA-256 database, family YARA rules, EICAR | Decisive: score 100 |
| Format indicators | Injection API combinations, packing, malformed headers, macro triggers, PDF actions, script behavior after decoding | Adds weight |
| Generic YARA rules | `resources/rules/generic_techniques.yar`: techniques, never family names | Adds weight |
| Learned models | EMBER2024 feature ensemble; MalConv2 for undecided Windows programs | Adds weight |
| Context | Mark of the Web on downloaded files | Small weight |

**Keeping false alarms down**

- Related traits share a capped group, so one trait type cannot reach Malicious alone,
  however many times it appears. Learned models are capped too, so they also need
  independent support.
- A rule that restates a capability shares that capability's group, so one fact is not
  counted twice.
- Large runtimes that import hundreds of APIs get less weight for API combinations.
- A valid Authenticode or catalog signature lowers heuristic and model weight, and holds
  a signed file below Suspicious unless a learned model also objects. It never overrides
  an exact-identity match. Stolen certificates are a known limit of this choice.

Confidence depends on how many independent groups agree, and drops when inspection was
incomplete.

Double-click any finding in **Scan** or **Quarantine** to see why it was flagged.

## File types

Types are decided by content, and the extension is only a hint.

| Analyzed | Windows programs, DOS programs, ELF, Mach-O, APK, DEX, JAR, Office files with macros, PDF, RTF, HTML, shortcuts, PowerShell, VBScript, JavaScript, batch, shell, Python, Perl, PHP, Ruby, Lua |
| --- | --- |
| Archives read recursively in memory | ZIP (including AES), TAR, GZIP, BZIP2, XZ, 7z. RAR needs an `unrar` tool on the machine; without one, RAR files are reported as not inspected |
| Not analyzed, and reported as such | Boot-sector and disk images, CAB, ISO, and unknown binary data |

Archive limits are depth 4, 4,096 entries, 64 MiB per member, 512 MiB in total, a 200:1
expansion ratio and 60 seconds. Reaching one is reported as an omission, and an extreme
ratio also counts as evidence. The common sample-sharing passwords are tried on
encrypted archives. Anything still unreadable is reported, and scores slightly higher if
it lists a program inside.

Files over the size limit (100 MiB by default) still get a hash check and inspection of
their start and end, and the scan reports that coverage was partial.

## Scan modes

| Mode | Covers |
| --- | --- |
| Quick | Downloads, Desktop, Temp, Startup and Public folders, plus running programs and autorun entries |
| Full | Every file on all fixed drives |
| Custom | The folders or files you choose |

Scheduled scans can use any of these. A hung or crashing file costs only that file: the
worker restarts and the scan continues after it.

## Real-time protection

Protection starts with the app and watches Downloads, Desktop, Documents, Temp and
Startup. You can change the list on the protection page. Partial browser downloads wait
until the final rename. Locked files are retried with increasing delays.

**Limit:** files are checked right after they are written. Without a kernel driver,
SentinelAV cannot guarantee blocking a file before it runs.

## Automatic quarantine

Automatic quarantine applies only when all of these are true:

- The verdict is Malicious, the score is 85 or higher and confidence is High.
- The file has no valid trusted signature, unless an exact-identity match applies.
- The file is a whole file in a watched folder, not an archive member. A match found only
  in decoded content stays manual.
- A fresh scan immediately before acting still agrees.
- It is not in Windows, Program Files or SentinelAV's own folders, which are always refused.

It is rate limited, pauses after repeated failures, and never stops a process. A file you
restored yourself stays where you put it. Change this under Settings → Defense → Response
Policy.

## Removal

- **Quarantine** encrypts the file with AES-256-GCM in authenticated chunks, using a key
  protected by Windows DPAPI for your account, checks the result, and only then deletes
  the original. Tampering or truncation is detected when an item is restored.
- **Restore** verifies the content and never overwrites an existing file.
- **Permanent delete** removes the encrypted copy. **Remove Permanently** quarantines the
  file first, then deletes it.
- **Stop process** needs a fresh Malicious verdict on the program's file and a matching
  process identity. It refuses critical processes, other users' processes and SentinelAV.

Same-account malware or an administrator can still interfere with the vault. Preventing
that would need a kernel driver and code signing.

## Command line

```powershell
.\.venv\Scripts\python.exe app.py --scan quick
.\.venv\Scripts\python.exe app.py --scan full
.\.venv\Scripts\python.exe app.py --scan "C:\Some\Folder"
```

These print JSON and never change files. Exit code 0 means nothing was flagged, 1 means
there are findings, and 2 means the scan could not run.

## Other limits

- The signed PE model has an expiry date. After it passes, model detection stops and
  scans report that it is unavailable, until a newer signed model is installed.
- Static analysis cannot see behavior that appears only at runtime. Behavior monitoring
  covers some of that, and reports suspicion rather than proof.
- See the evaluation report in the [documentation index](README.md) for measured
  detection and false-positive rates.
