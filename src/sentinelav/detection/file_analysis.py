# Purpose: Combine signatures, indicators, models and context into one assessment per object.
# Works with: detection.file_types, detection.indicators, detection.threat_score, detection.trust
# Used by: detection.engine, detection.scan_flow

"""Combine signatures, indicators, models and context into one assessment per object.

Nothing here executes inspected content. Emulation, when explicitly enabled, is a
virtual CPU inside the isolated worker and is off by default.
"""
import hashlib
from pathlib import Path
from sentinelav.detection.file_formats import pe_metadata,static_analysis
from sentinelav.detection.file_types import classify
from sentinelav.detection.indicators import collect
from sentinelav.detection.threat_score import arm_scores,automatic_eligible,indicator,score

GRAY_LOW=15
# 0 of 591 programs from the calibration products reached 0.5, so these bands sit well above ordinary software.
ELEVATED_SCORE=.9
NOTABLE_SCORE=.7
GRAY_HIGH=70
TRUST_CHECK_FROM=25
MEMBER_MODEL_BYTES=64*1024*1024
PARENT_MODEL_BYTES=256*1024*1024
PARENT_MODEL_MEMBERS=200
MAX_FINDINGS=2000
OVERSIZE_HASH_LIMIT=4*1024**3
OVERSIZE_SAMPLE=32*1024*1024
FIELDS=('score','verdict','confidence','threat_name','trusted_signature','indicators','groups','arms','file_kind','platform','automatic_response_eligible')


def signature_items(names,matches):
    """Exact-identity evidence is decisive and carries its own threat name."""
    items=[]
    for name in names:
        if name.startswith('SHA-256: '):items.append(indicator('hash_match','identity',100,name,'hash'))
        elif name.startswith('YARA: '):items.append(indicator('family_rule','identity',100,name,'family_yara'))
        elif name.startswith('EICAR'):items.append(indicator('eicar_test_file','identity',100,name,'test_marker'))
        elif name.startswith('AMSI: '):items.append(indicator('amsi_block','identity',100,name,'amsi'))
        else:items.append(indicator('derived_signature','identity',100,name,'derived_signature'))
        items[-1]['threat']='EICAR-Test-File' if name.startswith('EICAR') else name.split(': ',1)[-1][:80]
    for match in matches:
        if match.get('scope')=='generic':
            items.append(indicator('yara_'+match['rule'],match.get('group','generic_yara'),match.get('weight',15),match.get('description') or match['rule'],'generic_yara',match.get('category','')))
    return items


def _model_items(decision):
    items=[];coverage=decision.get('coverage',{})
    model=coverage.get('model',{})
    value=model.get('model_score')
    if isinstance(value,(int,float)):
        if model.get('review'):
            weight=55 if value>=.999 else 45
            items.append(indicator('learned_pe_model','ml',weight,f'A machine-learning model trained on PE features rates this file {value:.1%} likely malicious.','ml'))
        elif value>=ELEVATED_SCORE:
            items.append(indicator('learned_pe_model_elevated','ml',35,f'A machine-learning model gives an elevated score of {value:.1%}, below its alert threshold.','ml'))
        elif value>=NOTABLE_SCORE:
            items.append(indicator('learned_pe_model_notable','ml',20,f'A machine-learning model gives a notable score of {value:.1%}. This is weak evidence on its own.','ml'))
    return items


def _decision_items(decision):
    items=_model_items(decision)
    for fact in decision.get('evidence',[]):
        source=fact.get('source')
        if fact.get('confirmed'):
            layer='fusion' if source=='fusion' else 'derived_signature'
            for reason in fact.get('details',{}).get('reasons',[]) or [fact['description']]:
                entry=indicator('derived_'+str(source),'identity',100,f'Decoded content ({source}): {reason}',layer)
                entry['threat']=str(reason).split(': ',1)[-1][:80]
                items.append(entry)
        elif source=='emulation':
            items.append(indicator('emulated_behavior','emulation',32,fact['description'],'heuristic','Trojan'))
        elif source=='reputation':
            items.append(indicator('signed_reputation','reputation',40,fact['description'],'reputation'))
    return items


def neural_item(data):
    from sentinelav.detection.neural_bytes import predict
    output=predict(data)
    if output['review']:
        return indicator('learned_byte_model','ml',30,f"A raw-byte neural network rates this file {output['model_score']:.1%} likely malicious.",'ml'),output
    return None,output


def mark_of_the_web(path):
    """Downloaded files carry a Zone.Identifier stream; read it as context only."""
    try:
        with open(str(path)+':Zone.Identifier','r',encoding='utf-8',errors='replace') as stream:text=stream.read(4096)
    except OSError:return None
    for line in text.splitlines():
        if line.casefold().startswith('zoneid=') and line.split('=',1)[1].strip() in ('3','4'):
            return indicator('downloaded_from_internet','context',8,'The file was downloaded from the Internet (Mark of the Web).','context')
    return None


def parse_object(data,file_type):
    """A broken PE becomes evidence instead of skipping analysis."""
    try:
        metadata=pe_metadata(data)
        return metadata,static_analysis(data,metadata),''
    except (ValueError,IndexError,OverflowError) as error:
        metadata=dict(format='Other')
        message=str(error) if file_type['kind']=='pe' else ''
        return metadata,static_analysis(data,metadata),message


def public_fields(assessment):
    return {key:assessment[key] for key in FIELDS}


class FileAnalysisMixin:
    def add_finding(self,result,target,row):
        """Count every finding but bound what crosses the worker pipe."""
        result[target+'_total']=result.get(target+'_total',0)+1
        if len(result[target])<MAX_FINDINGS:result[target].append(row)

    def send_suspicious(self,result):
        send=getattr(self,'suspicious_finding',None)
        if send:
            for row in result['suspicious'][getattr(self,'suspicious_sent',0):]:send(row)
            self.suspicious_sent=len(result['suspicious'])

    def assess_object(self,data,suffix,names,matches,path=None,decision=None,metadata=None,analysis=None,malformed='',partial=False,extra=()):
        """Score one object. Omissions lower confidence and never read as clean."""
        file_type=classify(data,suffix)
        omissions=[]
        if metadata is None:metadata,analysis,malformed=parse_object(data,file_type)
        items=signature_items(names,matches)
        items.extend(collect(data,file_type,metadata,analysis,malformed,omissions))
        if decision:items.extend(_decision_items(decision))
        items.extend(extra)
        platform=file_type['platform']
        if file_type['kind']=='pe' and metadata.get('machine')=='0x8664':platform='Win64'
        current=score(items,platform,partial=partial)
        if (self.options.get('neural_gray') and not self.options.get('neural') and file_type['kind']=='pe'
                and GRAY_LOW<=current['score']<GRAY_HIGH):
            try:
                found,_=neural_item(data)
                if found:items.append(found)
            except Exception as error:omissions.append('Neural inference unavailable: '+str(error)[:160])
        if self.options.get('neural') and decision:
            neural=decision.get('coverage',{}).get('neural',{})
            if neural.get('review'):items.append(indicator('learned_byte_model','ml',30,f"A raw-byte neural network rates this file {neural['model_score']:.1%} likely malicious.",'ml'))
        if path:
            context=mark_of_the_web(path)
            if context:items.append(context)
        current=score(items,platform,partial=partial)
        trusted=False
        if path and file_type['kind'] in ('pe','data') and current['score']>=TRUST_CHECK_FROM and current['score']<100:
            from sentinelav.detection.trust import signature_status
            trusted=signature_status(path)=='trusted'
            if trusted:current=score(items,platform,trusted=True,partial=partial)
        current.update(arms=arm_scores(items,platform,trusted,partial),file_kind=file_type['kind'],platform=platform,
            analyzed=file_type['analyzed'],inert=file_type['inert'],omissions=omissions)
        current['automatic_response_eligible']=automatic_eligible(current)
        return current

    def assess_member(self,payload,name):
        """Full analysis for an archive member. Learned models spend a per-parent budget."""
        suffix=Path(str(name)).suffix.lower()
        sha=hashlib.sha256(payload).hexdigest()
        if sha in self.trusted_hashes:return [],[],[],None
        names,matches,errors=self.analyze_bytes(payload,sha)
        file_type=classify(payload,suffix)
        metadata,analysis,malformed=parse_object(payload,file_type)
        decision=None
        if self.advanced and file_type['kind']=='pe':
            if len(payload)>MEMBER_MODEL_BYTES or self.member_bytes+len(payload)>PARENT_MODEL_BYTES or len(self.member_seen)>=PARENT_MODEL_MEMBERS:
                errors=errors+['Learned-model budget reached for this archive member']
            elif sha not in self.member_seen:
                self.member_seen.add(sha);self.member_bytes+=len(payload)
                try:
                    decision=self.advanced.inspect(payload,Path('member'+suffix),sha,analysis,metadata,self.analyze_bytes,lambda:False)
                    self.current_scan_result.setdefault('embedded_model_analysis',[]).append(dict(
                        parent_path=self.current_parent,member_sha256=sha,bytes=len(payload),coverage=decision['coverage'],
                        verdict=decision['verdict'],omissions=decision['omissions'],automatic_response_eligible=False,
                        scope='Extracted or virtual bytes; no physical-file response authority'))
                except Exception as error:errors=errors+['Member analysis incomplete: '+str(error)[:160]]
        assessed=self.assess_object(payload,suffix,names,matches,decision=decision,metadata=metadata,analysis=analysis,malformed=malformed)
        return names,matches,errors+assessed['omissions'],assessed

    def inspect_oversized(self,path,resolved,result,capture_identity,cancelled):
        """Padding a file past the size limit must not hide it: inspect its identity, start and end."""
        result['skipped']+=1
        size=path.stat().st_size
        if size>OVERSIZE_HASH_LIMIT:
            result['errors'].append(f'{path}: Larger than 4 GiB; not inspected')
            return
        digest=hashlib.sha256();head=bytearray();tail=b''
        with path.open('rb') as stream:
            while chunk:=stream.read(1024*1024):
                if cancelled():return
                digest.update(chunk)
                if len(head)<OVERSIZE_SAMPLE:head.extend(chunk)
                else:tail=(tail+chunk)[-OVERSIZE_SAMPLE:]
        sha=digest.hexdigest()
        if sha in self.trusted_hashes:return
        result['errors'].append(f'{path}: Over the size limit; only its hash, start and end were inspected')
        sample=bytes(head)+tail
        names,matches,errors=self.analyze_bytes(sample,sha)
        result['errors'].extend(f'{path}: {error}' for error in errors)
        kind=classify(head,path.suffix)
        from sentinelav.detection.indicators import strings
        items=signature_items(names,matches)+strings.indicators(sample,kind['kind'])
        assessed=score(items,kind['platform'],partial=True)
        assessed.update(arms={},file_kind=kind['kind'],platform=kind['platform'])
        assessed['automatic_response_eligible']=automatic_eligible(assessed) and bool(names)
        if assessed['verdict']=='Clean':return
        target='detections' if assessed['verdict']=='Malicious' else 'suspicious'
        self.add_finding(result,target,dict(path=str(resolved),sha256=sha,reasons=names or assessed['reasons'],yara_matches=matches,oversized=True,
            detection_scope='partial',**public_fields(assessed)))
