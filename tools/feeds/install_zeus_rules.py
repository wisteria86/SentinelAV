# Purpose: Install only the explicitly reviewed Zeus-family text snapshots.
# Works with: paths
# Used by: the Python module loader or CLI entry point

"""Install only the explicitly reviewed Zeus-family text snapshots."""
import hashlib
import json
import re
from sentinelav.paths import PROJECT_ROOT,RESOURCE_ROOT

review=PROJECT_ROOT/'artifacts/evaluations/zeus-review'
rules=RESOURCE_ROOT/'rules'
catalog=json.loads((rules/'catalog.json').read_text())
for family,target,name,cap in (
    ('win.gameover_p2p','malpedia_gameover_p2p.yar','win_gameover_p2p_auto',598016),
    ('win.zeus','malpedia_zeus.yar','win_zeus_auto',319488),
):
    upstream=(review/(family+'_auto.yar')).read_bytes()
    text=upstream.decode('utf-8')
    revision=re.search(r'malpedia_hash = "([0-9a-f]{40})"',text)[1]
    if 'CC BY-SA 4.0' not in text: raise ValueError('Reviewed license missing')
    needle='7 of them and filesize < '+str(cap)
    if text.count(needle)!=1: raise ValueError('Reviewed threshold changed')
    text=text.replace(needle,'uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x00004550 and ('+needle+')')
    url='https://malpedia.caad.fkie.fraunhofer.de/yara/'+family
    changes='MZ/PE signature gates added; original patterns, seven-of threshold, size cap, metadata and disclaimer retained'
    text='// Felix Bilstein / Malpedia / yara-signator; CC-BY-SA-4.0\n// License: licenses/CC-BY-SA-4.0.txt\n// Source: '+url+'\n// Changes: '+changes+'\n'+text
    raw=text.encode('utf-8')
    (rules/target).write_bytes(raw)
    item=dict(file=target,sha256=hashlib.sha256(raw).hexdigest(),source_repository='https://malpedia.caad.fkie.fraunhofer.de',
              source_revision=revision,source_path='yara/'+family,source_url=url,upstream_sha256=hashlib.sha256(upstream).hexdigest(),
              license='CC-BY-SA-4.0',license_file='licenses/CC-BY-SA-4.0.txt',selected_rules=[name],
              coverage=family+' generated code patterns; memory/unpacked-derived, not all variants',changes=changes,
              reviewed='2026-11-02',review_scope='Source and condition review, then bounded clean-file and static guest validation; no broad efficacy claim',demo=False)
    catalog['files']=[f for f in catalog['files'] if f['file']!=target]+[item]
catalog['version']='2026.11.02.3'
(rules/'catalog.json').write_text(json.dumps(catalog,indent=2)+'\n',encoding='utf-8')
print('Installed two reviewed Zeus-family candidates with source hashes and CC-BY-SA notices.')
