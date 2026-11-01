"""Bounded YARA source loading with a pinned provenance catalog.

Source hashes provide local consistency, not tamper resistance or proof of
detection effectiveness. All runtime matching retains the engine's timeout.
"""
import hashlib
import json
from pathlib import Path
import re

MAX_FILES=64
MAX_FILE_BYTES=256*1024
MAX_TOTAL_BYTES=2*1024*1024


class RuleValidationError(ValueError):
    pass


def catalog(folder):
    path=Path(folder)/'catalog.json'
    if not path.exists(): return None
    if path.is_symlink() or path.stat().st_size>128*1024:
        raise RuleValidationError('YARA catalog is linked or oversized')
    try:
        value=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,ValueError) as error:
        raise RuleValidationError('Cannot read YARA catalog: '+str(error)) from None
    if not isinstance(value,dict) or value.get('schema')!=1 or not isinstance(value.get('files'),list):
        raise RuleValidationError('Unsupported YARA catalog')
    seen=set()
    if len(value['files'])>MAX_FILES: raise RuleValidationError('Too many catalog entries')
    for item in value['files']:
        if not isinstance(item,dict): raise RuleValidationError('Invalid catalog entry')
        name=item.get('file','')
        if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.yar(?:a)?',name)
                or name.casefold() in seen or not re.fullmatch(r'[0-9a-f]{64}',str(item.get('sha256','')))
                or not isinstance(item.get('selected_rules'),list) or not item['selected_rules']
                or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z_]\w*',n) for n in item['selected_rules'])):
            raise RuleValidationError('Invalid catalog filename, digest, or rule list')
        seen.add(name.casefold())
    return value


def sources(folder):
    folder=Path(folder).absolute()
    for part in [folder,*folder.parents]:
        if part.is_symlink() or part.is_junction():
            raise RuleValidationError('YARA directory cannot contain linked components')
    manifest=catalog(folder)
    managed={item['file']:item for item in manifest['files']} if manifest else {}
    files=[]
    if folder.exists():
        files+=list(folder.glob('*.yar'))+list(folder.glob('*.yara'))
    local=folder/'local'
    if local.exists():
        if local.is_symlink() or local.is_junction(): raise RuleValidationError('Linked local rule directory rejected')
        files+=list(local.glob('*.yar'))+list(local.glob('*.yara'))
    if len(files)>MAX_FILES: raise RuleValidationError('YARA rule file limit exceeded')
    actual={path.name for path in files if path.parent==folder}
    if set(managed)-actual: raise RuleValidationError('Managed YARA files are missing: '+', '.join(sorted(set(managed)-actual)))
    loaded={}
    metadata={}
    total=0
    for path in sorted(files,key=lambda p:str(p).casefold()):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_FILE_BYTES:
            raise RuleValidationError('Linked, nonregular, or oversized YARA file: '+path.name)
        relative=path.relative_to(folder).as_posix()
        namespace=re.sub(r'[^A-Za-z0-9_]','_',relative.rsplit('.',1)[0])
        if namespace in loaded: raise RuleValidationError('Duplicate YARA namespace: '+namespace)
        raw=path.read_bytes()
        total+=len(raw)
        if len(raw)>MAX_FILE_BYTES or total>MAX_TOTAL_BYTES: raise RuleValidationError('YARA source size limit exceeded')
        digest=hashlib.sha256(raw).hexdigest()
        item=managed.get(path.name) if path.parent==folder else None
        if item and digest!=item['sha256']:
            raise RuleValidationError('Managed YARA checksum mismatch: '+path.name)
        try: loaded[namespace]=raw.decode('utf-8-sig')
        except UnicodeError: raise RuleValidationError('YARA source is not UTF-8: '+path.name) from None
        metadata[namespace]=dict(item or {},file=relative,sha256=digest,managed=item is not None)
    return loaded,metadata,manifest


def compile_rules(folder):
    try: import yara
    except ImportError: return None,dict(available=False,status='Unavailable',warnings=['YARA unavailable: install yara-python to enable rule scanning'],public_rules=0,private_helpers=0,research_rules=0,demo_rules=0,local_rules=0,files=[]),{}
    loaded,metadata,manifest=sources(folder)
    summary=dict(available=True,status='No rules',warnings=[],public_rules=0,private_helpers=0,research_rules=0,demo_rules=0,local_rules=0,
                 files=list(metadata.values()),catalog_version=manifest.get('version') if manifest else None,
                 yara_version=yara.__version__,effectiveness_evaluation='Deferred')
    if not loaded:
        summary['warnings'].append('No YARA rules loaded; only hash/EICAR detection is available')
        return None,summary,metadata
    try:
        rules=yara.compile(sources=loaded,includes=False,error_on_warning=True)
    except (yara.Error,ValueError) as error:
        raise RuleValidationError('YARA compilation rejected the rule set: '+str(error)) from None
    counts={}
    for rule in rules:
        # The iterator does not expose namespaces. Exact declared rule names
        # are checked by compiling each small source independently below.
        if rule.is_private: summary['private_helpers']+=1
        else: summary['public_rules']+=1
    for namespace,source in loaded.items():
        try: unit=yara.compile(sources={namespace:source},includes=False,error_on_warning=True)
        except yara.Error as error: raise RuleValidationError('YARA file is not self-contained: '+str(error)) from None
        identifiers={r.identifier for r in unit}
        item=metadata[namespace]
        if item['managed'] and identifiers!=set(item['selected_rules']):
            raise RuleValidationError('Compiled rule names disagree with catalog: '+item['file'])
        public=sum(not r.is_private for r in unit)
        item['public_rules']=public
        item['private_helpers']=sum(r.is_private for r in unit)
        if item.get('demo'): summary['demo_rules']+=public
        elif item['managed']: summary['research_rules']+=public
        else: summary['local_rules']+=public
        counts[namespace]=public
    summary['status']='Compiled'
    return rules,summary,metadata


def evidence(match,metadata):
    item=metadata.get(match.namespace,{})
    return dict(rule=match.rule,namespace=match.namespace,file=item.get('file','Unknown'),
                description=str(match.meta.get('description',''))[:1000],
                license=item.get('license',str(match.meta.get('license','Unspecified'))),
                source=item.get('source_url',str(match.meta.get('source','Local rule'))),
                source_revision=item.get('source_revision','Unpinned local source'),
                source_sha256=item.get('sha256'),demo=bool(item.get('demo')),
                review_scope=item.get('review_scope','Local rule; no managed provenance review'),
                adaptations=item.get('changes','Local/unmanaged source'),
                effectiveness_evaluation='Deferred')
