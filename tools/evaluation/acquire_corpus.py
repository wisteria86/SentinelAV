# Purpose: Acquire only pinned archives into authenticated ciphertext, never raw files.
# Works with: lab.static_corpus, paths, response.response, workspace
# Used by: the Python module loader or CLI entry point

"""Acquire only pinned archives into authenticated ciphertext, never raw files."""
import hashlib
import json
import os
import urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sentinelav.lab.static_corpus import SPECS,HOLDOUT_SPECS,ZEUS_VALIDATION_SPECS,REVISION,AAD,validate_archive
from sentinelav.response.response import dpapi
from sentinelav.paths import PROJECT_ROOT


def main(holdout=False,zeus_validation=False):
    if holdout and zeus_validation: raise ValueError('Choose one fixed profile')
    from sentinelav.workspace import Workspace
    root=Workspace().area('lab')/('sealed-zeus-validation' if zeus_validation else 'sealed-static-holdout' if holdout else 'sealed-static-corpus')
    root.mkdir(exist_ok=False)
    key=AESGCM.generate_key(bit_length=256)
    records=[]
    for spec in ZEUS_VALIDATION_SPECS if zeus_validation else HOLDOUT_SPECS if holdout else SPECS:
        family=spec['family']
        url='https://raw.githubusercontent.com/ytisf/theZoo/'+REVISION+'/malware/Binaries/'+family+'/'+family+'.zip'
        with urllib.request.urlopen(url,timeout=30) as response: raw=response.read(spec['size']+1)
        metadata=validate_archive(raw,spec)  # Metadata only. Never open a member here.
        nonce=os.urandom(12)
        sealed=nonce+AESGCM(key).encrypt(nonce,raw,AAD+spec['id'].encode())
        name='corpus-'+spec['id']+'.sealed'
        (root/name).write_bytes(sealed)
        records.append(dict(id=spec['id'],family=family,file=name,source=url,sealed_bytes=len(sealed),
                            sealed_sha256=hashlib.sha256(sealed).hexdigest(),**metadata))
    (root/'transfer-key.dpapi').write_bytes(dpapi(key))
    (root/'acquisition.json').write_text(json.dumps(dict(revision=REVISION,files=records,
        host_storage='AES-256-GCM ciphertext',key_storage='CurrentUser DPAPI',
        host_raw_archive_stored=False,host_sample_unpacked=False,sample_executed=False),indent=2),encoding='utf-8')
    print('PASS: pinned encrypted archives verified; host storage contains authenticated ciphertext only.')

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--holdout',action='store_true')
    parser.add_argument('--zeus-validation',action='store_true')
    args=parser.parse_args()
    main(args.holdout,args.zeus_validation)
