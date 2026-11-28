# Purpose: Evaluate inert transformation fixtures; never a real-malware efficacy score.
# Works with: lab.corpus_evaluation, paths, platform.core.engine_policy, workspace
# Used by: tests.unit.test_coverage_evaluation

"""Evaluate inert transformation fixtures; never a real-malware efficacy score."""

import base64
from datetime import datetime, timezone
import gzip
import hashlib
import html
import io
import json
from pathlib import Path
import tarfile
import uuid
import zipfile
import zlib
from sentinelav.lab.corpus_evaluation import evaluate
from sentinelav.paths import PROJECT_ROOT
from sentinelav.platform.core.engine_policy import inspection_options


def fixture_cases():
    marker = b'SENTINELAV_DEMO_THREAT_7C23A'

    def zipped(name, payload):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
        return stream.getvalue()

    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as stream:
        entry = tarfile.TarInfo('document.txt')
        entry.size = len(marker)
        entry.mtime = 0
        stream.addfile(entry, io.BytesIO(marker))
    positive = {
        'raw.txt': marker,
        'renamed.bin': marker,
        'utf16.txt': b'\xff\xfe' + marker.decode().encode('utf-16le'),
        'base64.ps1': base64.b64encode(marker),
        'base64-utf16.ps1': base64.b64encode(marker.decode().encode('utf-16le')),
        'double-base64.js': base64.b64encode(base64.b64encode(marker)),
        'concatenated.js': b'"' + marker[:12] + b'" + "' + marker[12:] + b'"',
        'escaped.js': b'"' + b''.join(('\\x%02x' % byte).encode() for byte in marker) + b'"',
        'single.zip': zipped('document.txt', marker),
        'nested.zip': zipped('inner.zip', zipped('document.txt', marker)),
        'content.gz': gzip.compress(marker, mtime=0),
        'content.tar': archive.getvalue(),
        'stream.pdf': b'%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n'
        + zlib.compress(marker)
        + b'\nendstream\n%%EOF',
        'inline.html': b'<html><script>"' + base64.b64encode(marker) + b'"</script></html>',
    }
    cases = [
        dict(path=name, content=content, expected_detection=True, category='marker transformation')
        for name, content in positive.items()
    ]
    # Negative controls include format/encoding lookalikes without the marker.
    ordinary = b'Ordinary generated project notes: meeting at 14:30, version 12.'
    negative = {
        'ordinary.txt': ordinary,
        'ordinary.json': json.dumps({'notes': ordinary.decode()}).encode(),
        'ordinary.xml': b'<notes>' + ordinary + b'</notes>',
        'ordinary.html': b'<html><body>' + ordinary + b'</body></html>',
        'ordinary.ps1': b'# ' + ordinary,
        'ordinary.js': b'"' + base64.b64encode(ordinary) + b'"',
        'ordinary-utf16.txt': b'\xff\xfe' + ordinary.decode().encode('utf-16le'),
        'ordinary.zip': zipped('notes.txt', ordinary),
        'ordinary.gz': gzip.compress(ordinary, mtime=0),
    }
    cases.extend(
        dict(path=name, content=content, expected_detection=False, category='negative control')
        for name, content in negative.items()
    )
    cases.append(
        dict(
            path='unsupported.7z',
            content=b'7z\xbc\xaf\x27\x1cInert format-gap fixture',
            expected_detection=None,
            category='unsupported format',
        )
    )
    return cases


def summarize(rows):
    counts = dict(
        expected_positive=0,
        observed_positive=0,
        observed_positive_with_gaps=0,
        complete_misses=0,
        inconclusive_positive=0,
        negative_controls=0,
        unexpected_fixture_alerts=0,
        negative_without_alert=0,
        inconclusive_negative=0,
        gap_probes=0,
        gaps_reported=0,
    )
    for row in rows:
        expectation = row.get('expected_detection')
        outcome = row['outcome']
        detected = outcome in ('detected', 'detected_incomplete')
        if expectation is True:
            counts['expected_positive'] += 1
            if detected:
                counts['observed_positive'] += 1
                counts['observed_positive_with_gaps'] += int(not row['coverage_complete'])
            elif row['coverage_complete']:
                counts['complete_misses'] += 1
            else:
                counts['inconclusive_positive'] += 1
        elif expectation is False:
            counts['negative_controls'] += 1
            if detected:
                counts['unexpected_fixture_alerts'] += 1
            elif row['coverage_complete']:
                counts['negative_without_alert'] += 1
            else:
                counts['inconclusive_negative'] += 1
        else:
            counts['gap_probes'] += 1
            counts['gaps_reported'] += int(not row['coverage_complete'])
    return counts


def render(report):
    esc = lambda value: html.escape(str(value), quote=True)
    blocks = []
    for name, profile in report['profiles'].items():
        rows = ''.join(
            '<tr>'
            + ''.join(
                '<td>' + esc(row.get(key, '')) + '</td>'
                for key in ('path', 'expected_detection', 'outcome', 'coverage_complete')
            )
            + '</tr>'
            for row in profile['rows']
        )
        blocks.append(
            '<h2>'
            + esc(name)
            + '</h2><pre>'
            + esc(json.dumps(profile['metrics'], indent=2))
            + '</pre>'
            '<table><tr><th>Fixture</th><th>Expected alert</th><th>Observed</th><th>Inspection complete</th></tr>'
            + rows
            + '</table>'
        )
    notes = ''.join(
        '<li>'
        + esc(item.get('path', ''))
        + ': '
        + esc(item.get('meaning', item.get('reason', '')))
        + '</li>'
        for item in report.get('external_interference', []) + report.get('excluded_cases', [])
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelAV coverage evaluation</title>'
        '<style>body{font:15px Segoe UI;background:#fff8ee;color:#302217;margin:32px;max-width:1100px}h1,h2{color:#c95d14}table{border-collapse:collapse;width:100%}td,th{padding:9px;border:1px solid #dfd0bb;text-align:left}</style>'
        '<h1>Safe transformation coverage</h1><p>Inert known-marker fixtures and generated negative controls. '
        'This is not a malware detection rate. Inspection gaps are retained separately from misses.</p>'
        + ('<ul>' + notes + '</ul>' if notes else '')
        + ''.join(blocks)
        + '</html>'
    )


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    from sentinelav.workspace import Workspace

    work = Workspace()
    corpus = work.area('lab') / 'coverage-fixtures' / stamp
    output = work.area('evaluations') / ('coverage-' + stamp)
    corpus.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    entries = []
    for case in fixture_cases():
        payload = case['content']
        (corpus / case['path']).write_bytes(payload)
        entries.append(
            {
                **{key: value for key, value in case.items() if key != 'content'},
                'sha256': hashlib.sha256(payload).hexdigest(),
                'label': 'test',
                'provenance': 'Generated inert SentinelAV marker/negative control; no malware',
            }
        )
    manifest = corpus / 'manifest.json'
    manifest.write_text(json.dumps(dict(schema=1, files=entries), indent=2))
    profiles = {}
    for name, options in [
        ('baseline', {}),
        ('content', dict(advanced=True, content=True, documents=True)),
    ]:
        profile = evaluate(manifest, options=options)
        profile['options'] = inspection_options({**options, 'amsi': False})
        profile['metrics'] = summarize(profile['rows'])
        profiles[name] = profile
    report = dict(
        created_utc=datetime.now(timezone.utc).isoformat(),
        profiles=profiles,
        excluded_cases=[
            dict(
                path='document.rtf',
                reason='Encoded RTF marker fixture removed from host suite after Windows Defender intervention on 2026-11-03; not restored or regenerated',
            )
        ],
        corpus=str(manifest),
        real_malware=False,
        files_executed=False,
        interpretation='Known-marker transformation coverage only; not malware efficacy or population false-positive rate',
    )
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (output / 'report.html').write_text(render(report), encoding='utf-8')
    print(
        json.dumps(
            dict(
                report=str(output / 'report.html'),
                profiles={name: p['metrics'] for name, p in profiles.items()},
            ),
            indent=2,
        )
    )


if __name__ == '__main__':
    main()
