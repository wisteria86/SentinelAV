# Purpose: Install the specifically reviewed text-rule snapshots, not an auto updater.
# Works with: paths
# Used by: the Python module loader or CLI entry point

"""Install the specifically reviewed text-rule snapshots, not an auto updater."""

import hashlib
import json
from pathlib import Path
import re
import shutil
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT

review = PROJECT_ROOT / 'artifacts/evaluations/rule-review'
rules = RESOURCE_ROOT / 'rules'
catalog = json.loads((rules / 'catalog.json').read_text(encoding='utf-8'))
specs = [
    dict(
        source='rl_wannacry.yar',
        target='rl_wannacry.yar',
        name='Win32_Ransomware_WannaCry',
        license='MIT',
        license_file='licenses/ReversingLabs-MIT.txt',
        revision='e0a0be54aa1e11ccfd6854e4f19e9476f328fd84',
        repository='https://github.com/reversinglabs/reversinglabs-yara-rules',
        path='yara/ransomware/Win32.Ransomware.WannaCry.yara',
        coverage='WannaCry entry-point and long function patterns',
        changes='No rule body changes; attribution/license comment prepended',
    ),
    dict(
        source='rl_emotet.yar',
        target='rl_emotet.yar',
        name='Win32_Trojan_Emotet',
        license='MIT',
        license_file='licenses/ReversingLabs-MIT.txt',
        revision='e0a0be54aa1e11ccfd6854e4f19e9476f328fd84',
        repository='https://github.com/reversinglabs/reversinglabs-yara-rules',
        path='yara/trojan/Win32.Trojan.Emotet.yara',
        coverage='Emotet resource decryption plus filename/state-machine/decompression pattern pairs',
        changes='All original OR branches grouped under the MZ gate; original patterns and metadata retained',
    ),
    dict(
        source='malpedia_vmzeus.yar',
        target='malpedia_vmzeus.yar',
        name='win_vmzeus_auto',
        license='CC-BY-SA-4.0',
        license_file='licenses/CC-BY-SA-4.0.txt',
        revision='53a643781c18e08f4a50949af60172d837a0b6f6',
        repository='https://malpedia.caad.fkie.fraunhofer.de',
        path='yara/win.vmzeus',
        coverage='VMZeus generated static code sequences; unpacked/memory-derived source, limited generalization',
        changes='MZ and PE signature gates added; original seven-of-ten threshold, size cap, patterns, metadata and disclaimer retained',
    ),
]
for spec in specs:
    upstream = (review / spec['source']).read_bytes()
    text = upstream.decode('utf-8')
    if spec['target'] == 'rl_emotet.yar':
        prefix, body = text.rsplit('    condition:', 1)
        match = re.fullmatch(r'\s*uint16\(0\) == 0x5A4D and\s*(.*?)\s*}\s*', body, re.S)
        if not match:
            raise ValueError('Reviewed Emotet condition changed')
        text = (
            prefix
            + '    condition:\n        uint16(0) == 0x5A4D and (\n'
            + match[1]
            + '\n        )\n}\n'
        )
    elif spec['target'] == 'malpedia_vmzeus.yar':
        if spec['revision'] not in text:
            raise ValueError('Malpedia revision changed')
        needle = '7 of them and filesize < 475136'
        if text.count(needle) != 1:
            raise ValueError('Reviewed VMZeus condition changed')
        text = text.replace(
            needle,
            'uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x00004550 and (' + needle + ')',
        )
    url = (
        (spec['repository'] + '/blob/' + spec['revision'] + '/' + spec['path'])
        if spec['license'] == 'MIT'
        else 'https://malpedia.caad.fkie.fraunhofer.de/yara/win.vmzeus'
    )
    attribution = (
        'Copyright (c) 2020 ReversingLabs'
        if spec['license'] == 'MIT'
        else 'Felix Bilstein / Malpedia / yara-signator; source metadata and disclaimer retained'
    )
    text = (
        '// '
        + attribution
        + '\n// License: '
        + spec['license']
        + '; '
        + spec['license_file']
        + '\n// Source: '
        + url
        + '\n// Changes: '
        + spec['changes']
        + '\n'
        + text
    )
    raw = text.encode('utf-8')
    (rules / spec['target']).write_bytes(raw)
    item = dict(
        file=spec['target'],
        sha256=hashlib.sha256(raw).hexdigest(),
        source_repository=spec['repository'],
        source_revision=spec['revision'],
        source_path=spec['path'],
        source_url=url,
        upstream_sha256=hashlib.sha256(upstream).hexdigest(),
        license=spec['license'],
        license_file=spec['license_file'],
        selected_rules=[spec['name']],
        coverage=spec['coverage'],
        changes=spec['changes'],
        reviewed='2026-11-02',
        review_scope='Source/condition and licensing review; bounded static regression/holdout and benign evaluation; no broad efficacy claim',
        demo=False,
    )
    catalog['files'] = [f for f in catalog['files'] if f['file'] != spec['target']] + [item]
shutil.copyfile(review / 'RL-MIT.txt', rules / 'licenses/ReversingLabs-MIT.txt')
shutil.copyfile(review / 'CC-BY-SA-4.0.txt', rules / 'licenses/CC-BY-SA-4.0.txt')
catalog['version'] = '2026.11.02.2'
(rules / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n', encoding='utf-8')
print(
    'Installed 3 reviewed candidate rules with pinned digests, attribution and component licenses.'
)
