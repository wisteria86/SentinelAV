# Purpose: Offline publisher signing, optional download, and explicit verified activation.
# Works with: updates.artifacts
# Used by: the Python module loader or CLI entry point

"""Offline publisher signing, optional download, and explicit verified activation."""
import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sentinelav.updates.artifacts import bounded_json,canonical,activate,download


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    sign=sub.add_parser('sign')
    sign.add_argument('payload',type=Path); sign.add_argument('--key',required=True,type=Path)
    sign.add_argument('--key-id',required=True); sign.add_argument('--kind',required=True,choices=('model','reputation','policy'))
    sign.add_argument('--revision',required=True,type=int); sign.add_argument('--valid-days',type=int,default=7)
    sign.add_argument('--output',required=True,type=Path)
    install=sub.add_parser('activate')
    install.add_argument('envelope',type=Path); install.add_argument('--store',required=True,type=Path)
    install.add_argument('--trust',required=True,type=Path); install.add_argument('--kind',required=True,choices=('model','reputation','policy'))
    fetch=sub.add_parser('download'); fetch.add_argument('url'); fetch.add_argument('--output',required=True,type=Path)
    keygen=sub.add_parser('keygen'); keygen.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.command=='download': download(args.url,args.output); return
    if args.command=='activate':
        print(json.dumps(activate(args.envelope,args.store,args.trust,args.kind))); return
    if args.command=='keygen':
        password=getpass.getpass('New private-key encryption password: ').encode()
        if len(password)<12: raise ValueError('Use at least 12 characters')
        key=Ed25519PrivateKey.generate()
        with args.output.open('xb') as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password)))
        print('Public key (pin separately after review): '+key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())
        return
    if not 1<=args.valid_days<=90 or args.revision<1: raise ValueError('Invalid validity/revision')
    password=getpass.getpass('Private-key encryption password: ').encode()
    key=serialization.load_pem_private_key(args.key.read_bytes(),password=password)
    if not isinstance(key,Ed25519PrivateKey): raise ValueError('Ed25519 signing key required')
    payload=bounded_json(args.payload)
    manifest=dict(kind=args.kind,key_id=args.key_id,revision=args.revision,issued=int(time.time()),
        expires=int(time.time())+args.valid_days*86400,payload_sha256=hashlib.sha256(canonical(payload)).hexdigest())
    envelope=dict(schema=1,manifest=manifest,payload=payload,signature=base64.b64encode(key.sign(canonical(manifest))).decode())
    with args.output.open('x',encoding='utf-8') as stream: json.dump(envelope,stream,indent=2,allow_nan=False)
    print('Signed publisher artifact written. Trust pins and HTTPS hosting are configured separately.')


if __name__=='__main__': main()
