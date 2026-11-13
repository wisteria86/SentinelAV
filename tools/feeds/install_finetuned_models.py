# Purpose: Install the locally fine-tuned EMBER2024 ensemble and its confirmation model from pinned files.
# Works with: detection.pe_ensemble, tools.feeds.install_benchmark_models, workspace
# Used by: the Python module loader or CLI entry point

"""Install the locally fine-tuned EMBER2024 ensemble and its confirmation model from pinned files."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from sentinelav.workspace import Workspace
from tools.feeds.install_benchmark_models import sign_and_activate

# SHA-256 of each model text, fixed when the fine-tune was accepted (finetune/HANDOFF.md, section 2).
RUNS={
 'final-v2':dict(kind='model',members={
  'PE':'63b5c560cf90d1cb221dfd86cf7d97990edd60e457fb332adbf1a8deb4b598f5',
  'Win32':'c19925a1e022d1ff64aa7697a7e1923b8735a8706c545d573ba879259a81c3a0',
  'Win64':'194885955e58e8c5367cf6f2e9342a6e1109c0936d9cfb91269e04e2b32c2954',
  'Dot_Net':'e671789dfb8342f0ad810a647ee75d222fb3344e9ff98068268e92120cd1aeee'}),
 # The second stage: it must score at least 0.64 for a final-v2 conviction to stand (threshold chosen on validation only).
 'final-v3':dict(kind='confirm_model',confirm_threshold=.64,members={
  'PE':'3e8ab7ebed27fc3c8844a0fe989012c4c721d718a4724165d57815d9b02e6119',
  'Win32':'ed488d740f6f9af659803e2f01d123c6cd8c2ba19f9e688f0bc2ba4ea398c589',
  'Win64':'a743ebdd6de5ec9be24c89a322ef76aeea153a76c44c718440e83ee08e6d7607',
  'Dot_Net':'1600b1ca5cb5ce2b1abf4c454c6b9f8b98970da6c9cc3d80cad76da3c3238378'})}


def install(source,run):
    spec=RUNS[run];folder=Workspace().area('models')/('ember2024-'+run);folder.mkdir(exist_ok=True)
    payload=json.loads((Path(source)/run/'ensemble-payload.json').read_text(encoding='utf-8'))
    for name,digest in spec['members'].items():
        text=payload['members'][name]['model_text']
        if hashlib.sha256(text.encode()).hexdigest()!=digest or payload['members'][name].get('model_sha256')!=digest:raise ValueError('Fine-tuned model integrity failed: '+name)
    if 'confirm_threshold' in spec:payload['confirm_threshold']=spec['confirm_threshold']
    shutil.copy2(Path(source)/run/'ensemble-payload.json',folder/'ensemble-payload.json')
    result=sign_and_activate(payload,spec['kind'],folder)
    print('Activated',run,'as',spec['kind'],result,flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',default=str(Workspace().root/'finetune'/'models'))
    parser.add_argument('--runs',default='final-v2,final-v3')
    args=parser.parse_args()
    for run in args.runs.split(','):install(args.source,run.strip())


if __name__=='__main__':main()
