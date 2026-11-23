# Runbook: proving 90% detection by 28 November

Every stage is one command. Run them **in order** from PowerShell inside the repository folder
(`C:\Users\pc\Downloads\sqlilab\sentinelav`). Each one writes a full log to
`F:\SentinelAV-Work\runs\` and finishes by printing a status report, also saved as
`F:\SentinelAV-Work\STATUS.txt`.

**To talk to Claude:** paste the contents of `STATUS.txt`. If a step failed, also attach the
log path printed on the last line. That is all Claude needs.

Keep the PC on and awake during the long steps. Don't run two steps at once.

| # | When | Command | Takes | What it tells you |
|---|------|---------|-------|-------------------|
| 0 | anytime | `.\scripts\eval\SentinelAV-Eval.ps1 -Step status` | seconds | Where the project stands right now |
| 1 | now | `... -Step tests` | ~2 min | Code is healthy (expect `OK` and `0 problem(s)`) |
| 2 | after 1 | `... -Step fp` | ~2 h | False alarms on ~4,500 clean programs on this PC |
| 3 | after 2 | `... -Step dev` | ~3 h | Detection on 812 recent Windows malware samples (practice set) |
| 4 | after Claude reviews 2 and 3 | `... -Step freeze` | ~5 min | Locks code and definitions; starts the waiting period |
| 5 | 3 days after 4 (the script tells you the exact time) | `... -Step collect` | ~1 h | Downloads malware first seen **after** the freeze |
| 6 | after 5 | `... -Step holdout` | ~3 h | **The real result** for your sir. Run it once. |

### Timeline that meets 28 November

- **By 15 Nov:** steps 1–3, then send the status to Claude.
- **By 17 Nov:** fixes, if any, then step 4 (freeze).
- **20 Nov:** steps 5 and 6.
- **21–27 Nov:** buffer and write-up.

### Reading the status report

- **A. Full product:** what a user actually gets (signatures + ML + rules). On dev samples this
  is inflated, because the signatures already know them. On the holdout it is honest.
- **B. Unseen-malware layers:** what the product catches without knowing the exact file
  (EMBER ML, capa, generic rules, ClamAV heuristics). This is the true "new malware" ability.
- **C. Rules only:** B without machine learning.
- **EMBER model alone:** the neural model's own share.
- **flagged** = Suspicious or Malicious. **Malicious** = convicted outright.
- **false alarms:** must stay at or below 0.1% Malicious. Every flagged clean program is listed.
- **missed by full product:** families and file types of the misses. Claude uses this to fix gaps.

### Rules while frozen (between steps 4 and 6)

- Don't press **Update ClamAV Signatures** or change code. The holdout must use the frozen
  state, or the result is no longer "unseen malware".
- If the code must change, tell Claude. The freeze then restarts, which costs another wait.

### If something goes wrong

- **"waiting for C: space":** normal. The Sandbox needs 10 GB free on C:. Free up space if it
  waits for more than 15 minutes.
- **"UNCOMMITTED code":** the freeze needs committed code. Ask Claude to commit.
- **Anything else:** paste `STATUS.txt` and the log path to Claude.
