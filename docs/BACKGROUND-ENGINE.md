# Background engine milestone — 0.8.0

## Usage

On Real-Time Protection, select folders/sources and optionally enable **Keep
monitoring when this window closes (current Windows session)** before Start
Protection. The default remains window-owned monitoring. Background mode starts
a separate, hidden process under the current Windows account. It persists
protection events while the desktop window is closed. Reopening the same data
directory reconnects to an active engine without starting a second monitor.
Stop Protection stops monitoring and releases the helper process so a later
start loads updated engine code and detection data.
Closing the window detaches instead of stopping background monitoring.

There is no service registration, elevation, boot-time protection, automatic
restart, malware execution, or automatic quarantine in this milestone. A user
can terminate the engine. It stops at sign-out/reboot. This is groundwork for a
future Windows service, not a tamper-resistant service implementation.

## Communication boundary

- Qt local named pipe using UserAccessOption, with a separate endpoint derived
  from each resolved data directory. The Windows pipe ACL restricts access to
  the current user. This is OS-based access control, not a separate password.
- The engine refuses administrator elevation. User-writable rules/settings
  must not become an elevated command broker.
- Versioned JSON only: status, start, stop, poll, shutdown. No pickle, shell
  command, executable path, rule path, sample import, or arbitrary response RPC.
- Engine resource paths are fixed by its own installation. Start reads saved
  monitoring policy from that user's SQLite database.
- One request per connection, bounded request/response size, three-second
  incomplete-request timeout, and at most eight active clients.
- Bounded telemetry queue and live replay buffer. Sequence cursors and engine
  epochs distinguish runs; replay gaps are visible. Retained SQLite events are
  the source for historical reports. The GUI does not insert delivered events
  a second time.
- The engine owns a separate Qt lock file; the GUI retains its existing lock.
  Existing pipe endpoints are never forcibly removed to obtain ownership.

This boundary does not protect against malware running as the same user or an
administrator, endpoint impersonation by the same user, or modification of
user-owned rules/database. Cross-account rejection is provided by Qt's pipe ACL
and has not been independently tested with another Windows account here.

## Health and failure behavior

Active status requires telemetry from the monitor. Source availability and
queue/persistence problems remain visible. Communication failure changes the
GUI to **Protection status unknown**. Response actions remain blocked until
monitoring is verified stopped. Start Protection can reconnect; it does not
create another monitor when one already runs. Policy changes require an explicit
stop/restart. The service must eventually add stronger identity verification,
protected installation/configuration, authenticated policy ownership, durable
crash recovery, and independently reviewed privilege separation.

## Verification

`python -m unittest tests.unit.test_background -v` checks the RPC allowlist, input limits,
endpoint separation, engine-owned resource paths, and saved-policy validation.

`python -m tests.ui.verify_background_ui` uses fresh temporary folders and harmless text
markers. It verifies actual detection after GUI exit, automatic reattachment,
event persistence without duplication, explicit stop, and helper shutdown.
It does not change Windows service configuration or use malware.
