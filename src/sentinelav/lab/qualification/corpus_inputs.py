# Purpose: Decode approved bounded guest inputs and scan their verified identities.
# Works with: detection.inspection, lab.qualification.guest_context, lab.qualification.guest_support, paths,
#   workspace
# Used by: lab.qualification.guest_inventory

"""Approved encrypted corpus and narrowly scoped remediation fixtures in guests."""
import base64
import hashlib
from pathlib import Path
import re


def unpack(context,root):
    """Decrypt one approved batch of specimens inside the guest and write each under its hash,
    verifying every identity.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sentinelav.workspace import unlinked
    inv=context['case']['parameters']['inventory_data']
    if inv.get('schema')!=1 or inv.get('approved') is not True or inv.get('role')!='qualification':raise ValueError('Approved qualification inventory required')
    files=inv.get('files',[])
    if not 1<=len(files)<=32:raise ValueError('Explicit batch of at most 32 specimens required')
    key=base64.b64decode(context['inventory_key'],validate=True)
    if len(key)!=32:raise ValueError('Invalid inventory transfer key')
    offset=context['case']['parameters'].get('offset',0);count=context['case']['parameters'].get('count',32)
    if type(offset) is not int or type(count) is not int or offset<0 or not 1<=count<=32:raise ValueError('Invalid corpus batch')
    files=files[offset:offset+count]
    if inv.get('positive_control'):files=[*files,inv['positive_control']]
    selected=[];seen=set()
    for entry in files:
        name=entry['blob']
        if not re.fullmatch('[a-zA-Z0-9_.-]{1,100}\\.sealed',name):raise ValueError('Invalid sealed blob name')
        if entry.get('label') not in ('malware','benign') or not re.fullmatch('[0-9a-f]{64}',entry.get('sha256','')):raise ValueError('Reviewed specimen identity required')
        if entry['sha256'] in seen:raise ValueError('Duplicate inventory specimen')
        seen.add(entry['sha256']);source=unlinked(Path('C:/SentinelAV-Input/Approved')/name)
        if source.stat().st_size>8*1024**2+28:raise ValueError('Sealed specimen above 8 MiB limit')
        sealed=source.read_bytes()
        if hashlib.sha256(sealed).hexdigest()!=entry['sealed_sha256']:raise ValueError('Sealed inventory changed')
        raw=AESGCM(key).decrypt(sealed[:12],sealed[12:],b'SentinelAV-qualified-corpus-v1')
        if len(raw)>8*1024**2 or hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise ValueError('Decoded inventory identity differs')
        path=root/(entry['sha256']+'.bin')
        with path.open('xb') as f:f.write(raw)
        selected.append({**entry,'path':str(path)})
    return selected


def scan_rows(context,root,entries):
    """Scan each unpacked specimen in an isolated scanner and turn the results into measurement rows.
    """
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.paths import RESOURCE_ROOT
    from .guest_context import options
    from .guest_support import projection
    samples=[];detections=[]
    for entry in entries:
        scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',max_mb=8,options=options(context['case']['mode']))
        try:scan=scanner.scan([Path(entry['path'])],lambda:False,lambda *a:None)
        finally:scanner.close()
        coverage=scan.get('advanced_analysis',{}).get('coverage',{})
        row=dict(sha256=entry['sha256'],label=entry['label'],scan=scan,candidate_model=coverage.get('model',{}),candidate_neural=coverage.get('neural',{}),
            postcheck_unchanged=Path(entry['path']).exists() and hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest()==entry['sha256'],
            coverage_complete=scan.get('status')=='Complete' and not scan.get('errors'))
        result=projection(row,context['case']['mode'],context['versions_digest']);result.update(qualification=True,
            declared_format=entry.get('format'),
            independently_selected=entry.get('independently_selected') is True,family=entry.get('family'),family_verified=entry.get('family_verified') is True,
            independent_control=entry.get('independent_control') is True,automatic_action_exercised=False)
        samples.append(result);detections.extend(scan.get('detections',[]))
    return samples,detections
