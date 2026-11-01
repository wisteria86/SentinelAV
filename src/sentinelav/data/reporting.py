"""Local exports. Escape HTML and neutralize spreadsheet formula prefixes."""
import csv
import html
import io
import json
from datetime import datetime
from sentinelav.platform.runtime import VERSION,ZONE


def snapshot(store):
    scans=store.history()
    events=store.events(5000)
    return dict(version=VERSION,exported=datetime.now(ZONE).isoformat(),scans=scans,
                protection_events=events,quarantine=store.quarantine(),
                summary=dict(scans=len(scans),files=sum(s['scanned'] for s in scans),
                             scan_detections=sum(len(s['detections']) for s in scans),
                             live_alerts=sum(e['level']=='Alert' for e in events),
                             warnings=sum(e['level']=='Warning' for e in events)))


def render_report(data,kind):
    if kind=='json':
        return json.dumps(data,indent=2)
    if kind=='csv':
        out=io.StringIO(newline='')
        writer=csv.writer(out)
        writer.writerow(['Date','Type','Files scanned','Detections','Result'])
        for scan in data['scans']:
            values=[scan['started'],scan.get('kind',''),scan['scanned'],len(scan['detections']),scan['status']]
            writer.writerow(["'"+str(v) if str(v).lstrip().startswith(('=','+','-','@')) else str(v) for v in values])
        return out.getvalue()
    esc=lambda value:html.escape(str(value),quote=True)
    rows=''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in [s['started'],s.get('kind',''),s['scanned'],len(s['detections']),s['status']])+'</tr>' for s in data['scans'])
    events=''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in [e['time'],e['kind'],e['level'],e['details']])+'</tr>' for e in data['protection_events'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelAV Security Report</title>'
            '<style>body{font:15px Segoe UI,sans-serif;margin:40px;color:#302217;background:#fff8ee}h1{color:#d96b19}table{border-collapse:collapse;width:100%;margin:20px 0}th,td{text-align:left;padding:10px;border:1px solid #dfd0bb;overflow-wrap:anywhere}th{background:#f5e6d1}small{color:#6b6053}</style>'
            '<h1>SentinelAV Security Report</h1><p>Exported '+esc(data['exported'])+' · v'+esc(data['version'])+'</p><p>'+esc(data['summary'])+'</p>'
            '<h2>Scan history</h2><table><tr><th>Date</th><th>Type</th><th>Files</th><th>Detections</th><th>Result</th></tr>'+rows+'</table>'
            '<h2>Protection and response events</h2><table><tr><th>Date</th><th>Event</th><th>Level</th><th>Details</th></tr>'+events+'</table>'
            '<small>Prototype findings require review. Results cover inspected sources and do not prove a system is clean. JSON includes full evidence and quarantine metadata.</small></html>')
