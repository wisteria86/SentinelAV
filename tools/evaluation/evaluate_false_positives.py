# Purpose: Measure false positives on installed software, split by product. Reads files and runs nothing.
# Works with: detection.inspection, detection.trust, paths, workspace
# Used by: the CLI, tests.unit.test_false_positive_evaluation

"""Measure false positives on installed software, split by product. Reads files and runs nothing.

Whole products go to one half, so rules tuned on the calibrate half cannot learn the
files reported from the other. Files are presumed benign: installed software is not
independently verified, so each flagged file still needs a human decision.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import time

SUFFIXES={'.exe','.dll','.sys','.scr','.ocx','.pyd','.ps1','.bat','.cmd','.vbs','.js','.py','.pdf','.doc','.docx','.docm','.xls','.xlsx','.xlsm','.rtf','.zip','.jar','.msi','.hta','.lnk'}
PRIVATE_FOLDERS={'documents','desktop','downloads','pictures','videos','music','onedrive','appdata'}
PROGRAM_SUFFIXES={'.exe','.dll','.sys','.scr','.ocx','.pyd','.msi'}
DOCUMENT_SUFFIXES={'.pdf','.doc','.docx','.docm','.xls','.xlsx','.xlsm','.rtf','.zip','.jar','.lnk'}
MAX_BYTES=64*1024*1024
SEED=20261109


def default_roots():
    env=os.environ.get
    roots=[env('ProgramFiles','C:/Program Files'),env('ProgramFiles(x86)','C:/Program Files (x86)'),str(Path(env('SystemRoot','C:/Windows'))/'System32')]
    roots+=[r'F:\Games',r'F:\EpicGames',r'F:\ComfyUI-Installs',r'F:\SteamCMD']
    return [Path(root) for root in roots if Path(root).is_dir()]


def refuse_private(root):
    """Personal files stay out of this evaluation, whatever is passed in."""
    parts={part.casefold() for part in Path(root).absolute().parts}
    if 'users' in parts and parts&PRIVATE_FOLDERS:raise ValueError('Personal folders are outside this evaluation: '+str(root))
    return Path(root)


def product_of(root,path):
    return Path(path).relative_to(root).parts[0].casefold()


def half_of(product):
    return 'calibrate' if int(hashlib.sha256(product.encode()).hexdigest()[:8],16)%2==0 else 'report'


def type_group(path):
    suffix=Path(path).suffix.casefold()
    return 'program' if suffix in PROGRAM_SUFFIXES else 'document' if suffix in DOCUMENT_SUFFIXES else 'script'


def select(roots,split,per_product,root_cap=60000):
    """Sample each product evenly, so one huge application cannot dominate the rate."""
    products=defaultdict(list)
    for root in roots:
        refuse_private(root)
        seen=0
        for folder,dirs,files in os.walk(root):
            dirs[:]=[d for d in dirs if not (Path(folder)/d).is_junction() and not (Path(folder)/d).is_symlink()]
            for name in files:
                if Path(name).suffix.casefold() not in SUFFIXES:continue
                path=Path(folder)/name;seen+=1
                product=product_of(root,path)
                # Sampled per type, so a product's many programs cannot crowd out its documents and scripts.
                if half_of(product)==split:products[(str(root),product,type_group(path))].append(path)
            if seen>root_cap:break
    generator=random.Random(SEED);chosen=[]
    for key,paths in sorted(products.items()):
        paths=sorted(paths);generator.shuffle(paths)
        chosen+=[(key,path) for path in paths[:per_product]]
    return chosen,len(products)


def upper_bound(failures,trials,confidence=.95):
    """One-sided exact (Clopper-Pearson) upper bound on a rate, using only the standard library."""
    if trials<=0:return 1.0
    if failures>=trials:return 1.0
    from math import comb
    def tail(rate):return sum(comb(trials,k)*rate**k*(1-rate)**(trials-k) for k in range(failures+1))
    low,high=failures/trials,1.0
    for _ in range(60):
        middle=(low+high)/2
        if tail(middle)>1-confidence:low=middle
        else:high=middle
    return high


def evaluate(chosen,budget):
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.detection.trust import signature_status
    from sentinelav.paths import RESOURCE_ROOT
    scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',max_mb=64,options=dict(score_all=True),persistent=True)
    deadline=time.monotonic()+budget
    rows=[];omitted=Counter();times=[]
    try:
        for (root,product,_),path in chosen:
            if time.monotonic()>deadline:
                omitted['time budget']+=1;continue
            try:
                if path.stat().st_size>MAX_BYTES:
                    omitted['over size limit']+=1;continue
                started=time.monotonic()
                result=scanner.scan([path],lambda:False,lambda *a:None)
                times.append(time.monotonic()-started)
            except (OSError,ValueError,RuntimeError) as error:
                omitted[type(error).__name__]+=1;continue
            item=result.get('assessment')
            if not item:
                omitted['not assessed']+=1;continue
            signed=signature_status(path)=='trusted' if item['file_kind'] in ('pe','dos_mz') else None
            row=dict(path=str(path),product=product,root=root,kind=item['file_kind'],verdict=item['verdict'],score=item['score'],confidence=item['confidence'],
                signed=signed,automatic=bool(item.get('automatic_response_eligible')),codes=[entry['code'] for entry in item.get('indicators',[])[:8]],arms=item.get('arms',{}),
                model_scores=item.get('model_scores',{}))
            rows.append(row)
    finally:
        scanner.close()
    return rows,omitted,times


def summarize(rows,omitted,times,products,split):
    def rate(subset,*verdicts):
        hits=sum(row['verdict'] in verdicts for row in subset)
        return dict(flagged=hits,files=len(subset),percent=round(100*hits/len(subset),3) if subset else None,upper_95_percent=round(100*upper_bound(hits,len(subset)),3))
    executables=[row for row in rows if row['kind'] in ('pe','dos_mz')]
    flagged_products=defaultdict(int)
    for row in rows:
        if row['verdict']!='Clean':flagged_products[row['product']]+=1
    times=sorted(times)
    return dict(split=split,products=products,files=len(rows),omitted=dict(omitted),malicious=rate(rows,'Malicious'),any_flag=rate(rows,'Malicious','Suspicious'),
        automatic_action_candidates=sum(row['automatic'] for row in rows),executables_any_flag=rate(executables,'Malicious','Suspicious'),
        unsigned_executables_any_flag=rate([row for row in executables if row['signed'] is False],'Malicious','Suspicious'),
        signed_executables_any_flag=rate([row for row in executables if row['signed']],'Malicious','Suspicious'),
        by_kind=Counter(row['kind'] for row in rows).most_common(),flagged_by_product=sorted(flagged_products.items(),key=lambda item:-item[1])[:25],
        indicators_on_flagged=Counter(code for row in rows if row['verdict']!='Clean' for code in row['codes']).most_common(25),
        seconds=dict(total=round(sum(times),1),median=round(times[len(times)//2],3) if times else None,slowest=round(times[-1],1) if times else None))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split',choices=('calibrate','report'),required=True)
    parser.add_argument('--per-product',type=int,default=60)
    parser.add_argument('--budget',type=int,default=7200,help='Total scanning seconds')
    parser.add_argument('--root',type=Path,action='append',help='Replaces the default installed-software locations')
    args=parser.parse_args(argv)
    from sentinelav.workspace import Workspace
    roots=[refuse_private(root) for root in (args.root or default_roots())]
    chosen,products=select(roots,args.split,args.per_product)
    print(f'{args.split}: {products} products, {len(chosen)} files selected',flush=True)
    # Measure the product as shipped: ClamAV signatures are the layer most likely to flag clean software.
    from sentinelav.detection.clamav_engine import ensure_service
    service,problem=ensure_service()
    print('ClamAV:',problem or 'running',flush=True)
    try:rows,omitted,times=evaluate(chosen,args.budget)
    finally:
        if service:service.stop()
    summary=summarize(rows,omitted,times,products,args.split)
    summary.update(created_utc=datetime.now(timezone.utc).isoformat(),roots=[str(root) for root in roots],ground_truth='Presumed benign installed software; not independently verified',files_executed=False,clamav=problem or 'running')
    output=Workspace().run('evaluations','benign-'+args.split)
    (output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    (output/'rows.json').write_text(json.dumps(rows),encoding='utf-8')
    print(json.dumps({key:summary[key] for key in ('files','omitted','malicious','any_flag','automatic_action_candidates','executables_any_flag','unsigned_executables_any_flag','signed_executables_any_flag','seconds','flagged_by_product','indicators_on_flagged')},indent=1))
    print('Evidence:',output)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
