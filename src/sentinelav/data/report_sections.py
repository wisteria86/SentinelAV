# Purpose: Render detection evidence, inspection omissions, and quarantine outcomes in HTML reports.
# Works with: data.reporting; ui.finalization

from html import escape


def table(title, columns, rows):
    """Render a titled HTML table, escaping every value. Shows 'None recorded' when there are no rows.
    """
    def cell(tag, text):
        """Wrap one escaped value in a <td> or <th> tag."""
        return f'<{tag}>'+escape(str(text), quote=True)+f'</{tag}>'
    rendered = ['<tr>'+''.join(cell('td', value) for value in row)+'</tr>' for row in rows]
    return ('<h2>'+escape(title)+'</h2><table><tr>'
            +''.join(cell('th', name) for name in columns)+'</tr>'
            +(''.join(rendered) or '<tr><td colspan="'+str(len(columns))+'">None recorded</td></tr>')+'</table>')


def evidence_sections(data):
    """Build the detailed evidence part of the HTML report: every finding, any gaps in scan coverage,
    and the quarantine history.
    """
    scans = data['scans']
    detections = [(scan['started'], finding['path'], finding.get('verdict', 'Malicious'), finding.get('score', ''), finding.get('confidence', ''),
                   finding.get('threat_name', ''), '; '.join(finding['reasons']), finding['sha256'])
                  for scan in scans for finding in scan['detections']+scan.get('suspicious', [])]
    omissions = [(scan['started'], scan.get('kind', ''), scan.get('skipped', 0),
                  '; '.join(scan.get('errors', [])), '; '.join(scan.get('warnings', [])),
                  scan.get('advanced_review_total', 0)) for scan in scans]
    quarantine = [(row.get('date', ''), row['original'], row['state'], row['sha256'])
                  for row in data.get('quarantine', [])]
    return (table('Scan findings', ['Date', 'File', 'Verdict', 'Score', 'Confidence', 'Threat', 'Why it was flagged', 'SHA-256'], detections)
            +table('Coverage and review requirements', ['Date', 'Scan', 'Oversized', 'Errors / omissions',
                    'Engine warnings', 'Analysis reviews'], omissions)
            +table('Quarantine and recovery', ['Date', 'Original file', 'State', 'SHA-256'], quarantine))
