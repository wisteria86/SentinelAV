# How to run SentinelAV

SentinelAV is a Windows anti-malware program written in Python (PySide6 desktop app,
separate scanning worker, background monitoring engine). This guide covers setting it up
from source, using it, testing it, building the installer, running the live demo and
repeating the evaluation.

> SentinelAV never runs a file to judge it. Malware samples used for testing are opened
> only inside an offline Windows Sandbox and are stored encrypted on the host.

## 1. Requirements

| Item | Needed for | Notes |
| --- | --- | --- |
| Windows 10 or 11, 64-bit | Everything | Windows 11 Pro was used for development |
| Python 3.12 (64-bit) | Running from source | Add to PATH during install |
| Git | Getting the code | |
| About 3 GB free disk | Python packages, models, definitions | |
| Windows Sandbox feature | Live demo and evaluations only | Windows Pro/Enterprise/Education; needs about 10 GB free on C: while running |
| 7-Zip (optional) | Reading CAB, Deflate64 ZIP and some 7z archives | Shipped inside the packaged app |

## 2. Get the code and install dependencies

```powershell
git clone https://github.com/wisteria86/SentinelAV.git
cd SentinelAV
git switch fix/holdout-gaps          # latest detection fixes and the live demo
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements/requirements.txt
```

The repository holds the source, reviewed YARA rules and a small hash overlay. Large
items are kept out of Git and are optional for a first run:

| Item | How to get it | Without it |
| --- | --- | --- |
| ClamAV engine and database | `scripts\Install-AnalysisDependencies.ps1`, then **Updates → Update definitions** in the app | ClamAV layer reports "unavailable"; other layers still work |
| Full hash feeds (MalwareBazaar, VirusShare) | `.\scripts\Download-Hashes.ps1` (see `docs/HASH-IMPORT.md`) | Only the small built-in hash list is used |
| Learned models (EMBER2024) | `tools\feeds\install_finetuned_models.py` with the trained model files | Model layer reports "unavailable" |

## 3. Start the desktop app

```powershell
.\start.ps1
```

or double-click the installed **SentinelAV** shortcut. The app opens on the **Dashboard**.

| Page | What to do there |
| --- | --- |
| Dashboard | Protection status, last scan, definitions date |
| Scan | Quick scan, Full scan or Custom scan of chosen folders |
| Real-Time Protection | Turn monitoring on or off, choose watched folders |
| Quarantine | Restore or permanently delete isolated files; double-click a finding for its reasons |
| Reports | Scan history, detections and exported HTML reports |
| Settings | Scanning options, exclusions, scheduling, Defense layers and response policy |

Application data (history, settings, encrypted quarantine) is stored in
`%LOCALAPPDATA%\SentinelAV`.

## 4. Scan from the command line

```powershell
.\.venv\Scripts\python.exe app.py --scan quick
.\.venv\Scripts\python.exe app.py --scan full
.\.venv\Scripts\python.exe app.py --scan "C:\Some\Folder"
```

The result is printed as JSON. Exit code `0` means nothing was flagged, `1` means
findings, `2` means the scan could not run. Command-line scans never change files.

## 5. Run the tests

```powershell
.\test.ps1        # structure check, theZoo-hardcoding guard, ~415 unit tests (about 2 minutes)
.\test.ps1 -UI    # the same, plus UI checks
```

End-to-end checks on harmless files (set `PYTHONPATH` to `src;.` first):

```powershell
.\.venv\Scripts\python.exe -m tests.integration.verify_protection_cycle
.\.venv\Scripts\python.exe -m tests.integration.verify_proposal_items
```

## 6. Build the executable and installer

```powershell
.\build.ps1              # packaged app (PyInstaller)
.\build.ps1 -Installer   # plus the Inno Setup installer
```

Output: `F:\SentinelAV-Work\builds\dist\SentinelAV\` (app) and
`F:\SentinelAV-Work\builds\release\` (installer). Verify an installer with
`scripts\verify_installer.ps1`.

## 7. Live demo: `SampleRun.bat`

`SampleRun.bat` opens SentinelAV in an offline Windows Sandbox and scans eight classic
theZoo samples (WannaCry, Petya, Emotet, Zeus, Agent Tesla, ILOVEYOU, Melissa, Mirai).

1. Turn on **Windows Sandbox** (*Turn Windows features on or off*), restart.
2. Make sure these exist next to `SampleRun.bat` (or at the F: paths it falls back to):

   | Folder | Contents | Source |
   | --- | --- | --- |
   | `demo\samples` | Encrypted samples and their keys | In the repository |
   | `demo-kit\SentinelAV` | Packaged app | Copy of `F:\SentinelAV-Work\builds\dist\SentinelAV` |
   | `demo-kit\definitions` | Frozen definitions | Copy of `F:\SentinelAV-Work\snapshots\eval-freeze-90` |

3. Close any open Windows Sandbox, then double-click `SampleRun.bat`.

The Sandbox has no network and is erased when closed. Inside it, the samples are
decrypted to theZoo's password-protected ZIPs, which SentinelAV reads in memory. After
about half a minute a window lists each sample's verdict, score, threat name and reasons;
the same results appear under **Reports** in the SentinelAV window.

Expected result (tested): all eight rated **Malicious, 100/100, High confidence** in about
21 seconds of scanning. To fetch a different theZoo sample, run
`.\.venv\Scripts\python.exe demo\fetch_sample.py <theZoo folder name>`.

## 8. Repeat the evaluation (optional, takes hours)

All malware handling happens in fresh offline Windows Sandboxes. Requires an abuse.ch
account key in the user environment variable `ABUSECH_AUTH_KEY`.

```powershell
.\scripts\eval\SentinelAV-Eval.ps1 -Step tests     # unit tests and guards (~2 min)
.\scripts\eval\SentinelAV-Eval.ps1 -Step fp        # false alarms on clean software (~2 h)
.\scripts\eval\SentinelAV-Eval.ps1 -Step dev       # dev malware set in the Sandbox (~3 h)
.\scripts\eval\SentinelAV-Eval.ps1 -Step freeze    # lock code and definitions
.\scripts\eval\SentinelAV-Eval.ps1 -Step collect   # after the wait: fetch post-freeze malware
.\scripts\eval\SentinelAV-Eval.ps1 -Step holdout   # the real test, run once (~1-3 h)
.\scripts\eval\SentinelAV-Eval.ps1 -Step status    # print the status report
```

Reports are written under `logs\<run>\report.md`; a summary is in
`F:\SentinelAV-Work\STATUS.txt`.

## 9. Troubleshooting

| Problem | Fix |
| --- | --- |
| "Windows Sandbox is not enabled" | Enable the feature and restart |
| Sandbox does not start or hangs | Free space on C: (about 10 GB), close any other Sandbox |
| "ClamAV unavailable" warning | Install ClamAV with `scripts\Install-AnalysisDependencies.ps1` and update definitions |
| Defender removes a sample or rule file | Expected for malware and YARA rule files; keep samples encrypted (`demo\fetch_sample.py` does this). Do not add Defender exclusions |
| Unit tests fail on temp paths | Run `test.ps1 -TempRoot <absolute path on a drive with space>` |
