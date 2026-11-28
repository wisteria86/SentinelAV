# Purpose: Track requested-source failures and coverage loss for a monitoring session.
# Works with: monitoring.monitor_loop; monitoring.monitoring; ui.protection_events

import psutil


class MonitoringHealth:
    """Loss stays visible until a new session; an empty queue cannot undo it."""

    def __init__(self):
        """Start with no recorded failures or losses."""
        self.failures = {}
        self.losses = {}

    def unavailable(self, source, reason):
        """Record that a telemetry source has failed, with the reason."""
        self.failures[source] = str(reason)[:500]

    def lost(self, source, count, *, cumulative=False):
        """Record that a source lost `count` observations. With cumulative=True, count is a running
        total from the source rather than a new amount.
        """
        count = max(0, int(count))
        if count:
            previous = self.losses.get(source, 0)
            self.losses[source] = max(previous, count) if cumulative else previous + count

    def status(self):
        """Summarise every failure and loss for the status display."""
        reasons = [f'{source}: {reason}' for source, reason in self.failures.items()]
        reasons += [
            f'{source}: {count} observations lost or unattributed'
            for source, count in self.losses.items()
        ]
        return dict(
            telemetry_error='; '.join(reasons),
            telemetry_failures=dict(self.failures),
            telemetry_losses=dict(self.losses),
        )


def verified_network_processes(connections, snapshot, exclusions, excluded):
    """Correlate only still-live PID/creation-time pairs after capturing connections."""
    verified = {}
    omitted = 0
    pids = {
        connection.pid
        for connection in connections
        if connection.status == 'ESTABLISHED' and connection.raddr
    }
    for pid in pids:
        info = snapshot.get(pid)
        if not info or not info.get('create_time'):
            omitted += 1
            continue
        if info.get('exe') and excluded(info['exe'], exclusions):
            continue
        try:
            if psutil.Process(pid).create_time() != info['create_time']:
                omitted += 1
                continue
        except psutil.Error:
            omitted += 1
            continue
        verified[pid] = info
    return verified, omitted
