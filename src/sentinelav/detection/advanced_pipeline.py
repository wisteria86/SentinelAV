# Purpose: Shared opt-in analysis used by GUI, background and protected-service scanners.
# Works with: detection.active_content, detection.classifier, detection.content_analysis, detection.decisions,
#   detection.documents
# Used by: detection.engine, tests.unit.test_analysis_artifacts

"""Shared opt-in analysis used by GUI, background and protected-service scanners."""
from pathlib import Path
import time
import re
from cryptography.exceptions import InvalidSignature
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.detection.decisions import Evidence,decide
from sentinelav.updates.artifacts import active


class AdvancedPipeline:
    def __init__(self,store=None,options=None):
        self.options=dict(options or {})
        self.store=Path(store) if store else RESOURCE_ROOT/'analysis-data'
        self.trust=Path(self.options.get('analysis_trust',RESOURCE_ROOT/'trusted-update-keys.json'))
        self._asset_stamp=None
        self._reload_assets()

    def _stamp(self):
        result=[]
        for path in (self.store/'active.json',self.trust):
            try:
                value=path.stat(); result.append((value.st_ino,value.st_size,value.st_mtime_ns))
            except OSError: result.append(None)
        return tuple(result)

    def _reload_assets(self):
        self.assets={}
        self.omissions=[]
        for kind in ('model','reputation','policy'):
            if not self.options.get('model' if kind=='policy' else kind,False): continue
            if kind=='policy':
                try:
                    from sentinelav.updates.artifacts import bounded_json
                    if kind not in bounded_json(self.store/'active.json',65536):continue
                except (OSError,ValueError):continue
            try:
                folder=self.store
                if kind=='model' and not (folder/'active.json').exists():folder=RESOURCE_ROOT/'analysis-data'
                payload,manifest=active(folder,self.trust,kind)
                self.assets[kind]=(payload,manifest)
            except (OSError,ValueError,KeyError,TypeError,InvalidSignature) as error:
                self.omissions.append(kind+' unavailable: '+str(error)[:160])
        self.reputation=None
        if 'reputation' in self.assets:
            from sentinelav.detection.reputation import ReputationIndex
            try: self.reputation=ReputationIndex(*self.assets['reputation'])
            except (ValueError,KeyError,TypeError) as error: self.omissions.append('Invalid reputation index: '+str(error)[:160])
        self._asset_stamp=self._stamp()

    def inspect(self,data,path,sha,analysis,format_info,analyze,cancelled,emulation=False):
        if self._stamp()!=self._asset_stamp: self._reload_assets()
        from sentinelav.detection.content_analysis import normalized_variants,inspect_containers,SCRIPT_SUFFIXES
        facts=[]; omissions=list(self.omissions); coverage={'model':dict(status='Unavailable' if self.options.get('model') else 'Disabled')}
        for signal in analysis.get('signals',[]):
            facts.append(Evidence('static',signal['code'],signal['explanation']))
        suffix=Path(path).suffix.lower()
        if self.options.get('content',True) and (suffix in SCRIPT_SUFFIXES or data.startswith((b'\xff\xfe',b'\xfe\xff'))):
            variants,errors=normalized_variants(data,suffix)
            coverage['normalization_variants']=len(variants)
            omissions.extend(errors)
            for method,payload in variants:
                if cancelled(): break
                reasons,matches,errors=analyze(payload)
                omissions.extend(errors)
                if reasons: facts.append(Evidence('normalized-content','concealed_content',
                    'Decoded content matches existing detection patterns',confirmed=True,details=dict(transform=method,reasons=reasons,yara_matches=matches)))
        # Archive formats get the recursive reader when it is enabled; PDF streams stay here.
        containers=self.options.get('content',True) and (not self.options.get('archives',True) or data.startswith(b'%PDF-'))
        nested,errors,_=inspect_containers(bytes(data),analyze,cancelled) if containers else ([],[],{})
        omissions.extend(errors)
        for item in nested:
            facts.append(Evidence('container','embedded_content','Embedded content matches detection patterns',confirmed=True,details=item))
        from sentinelav.detection.documents import macro_sources
        macros,errors=macro_sources(data) if self.options.get('documents',True) else ([],[])
        omissions.extend(errors)
        for name,source in macros:
            reasons,matches,errors=analyze(source)
            omissions.extend(errors)
            if reasons: facts.append(Evidence('macro','macro_content','Extracted macro source matches detection patterns',confirmed=True,details=dict(member=name,reasons=reasons,yara_matches=matches)))
        from sentinelav.detection.active_content import active_sources
        sources,errors=active_sources(data,suffix) if self.options.get('documents',True) else ([],[])
        omissions.extend(errors); coverage['active_content_sources']=len(sources)
        for name,source in sources:
            candidates=[('extracted',source)]
            if name.startswith('html'):
                decoded,errors=normalized_variants(source,'.js')
                candidates.extend(decoded); omissions.extend(errors)
            for transform,payload in candidates:
                if cancelled(): omissions.append('Active content cancelled'); break
                reasons,matches,errors=analyze(payload); omissions.extend(errors)
                if reasons: facts.append(Evidence('active-document','embedded_content',
                    'Extracted active-document content matches detection patterns',confirmed=True,
                    details=dict(member=name,transform=transform,reasons=reasons,yara_matches=matches)))
        if self.reputation:
            if time.time()>=self.assets['reputation'][1]['expires']:
                omissions.append('Signed reputation feed expired; reputation coverage unavailable')
                reputation_rows=[]
            else: reputation_rows=self.reputation.lookup(sha,bytes(data))
            for row in reputation_rows:
                if row['verdict']!='benign': facts.append(Evidence('reputation','threat_intelligence',
                    'Signed reputation entry: '+row['verdict'],details=row))
        if format_info.get('format')=='PE' and 'model' in self.assets:
            from sentinelav.detection.classifier import predict
            try:
                model,manifest=self.assets['model']
                if time.time()>=manifest['expires']: raise ValueError('Model has expired')
                if model.get('algorithm')=='lightgbm-pe-ensemble-v1':
                    from sentinelav.detection.pe_ensemble import predict as predict_ensemble
                    output=predict_ensemble(model,data)
                elif model.get('algorithm')=='lightgbm-pe-v1':
                    from sentinelav.detection.pe_classifier import predict as predict_pe
                    output=predict_pe(model,data)
                else:output=predict(model,analysis['features'])
                coverage['model']=dict(status='Complete',**output)
                if output['review']:
                    facts.append(Evidence('model','statistical_classification',f"Learned PE model score {output['model_score']:.1%} requests review",details=dict(**output,revision=manifest['revision'])))
            except Exception as error: omissions.append('Model inference unavailable: '+type(error).__name__+': '+str(error)[:200])
        if self.options.get('neural') and format_info.get('format')=='PE':
            try:
                from sentinelav.detection.neural_bytes import predict as predict_bytes
                neural=predict_bytes(data);coverage['neural']=neural
                if neural['status']!='Complete':omissions.append('Neural byte inspection reached its 4,000,000-byte prefix limit')
                if neural['review']:facts.append(Evidence('neural','byte_sequence_classification',f"Raw-byte neural model score {neural['model_score']:.1%} requests review",details=neural))
            except Exception as error:
                coverage['neural']=dict(status='Unavailable',reason=str(error)[:200]);omissions.append('Neural inference unavailable: '+str(error)[:200])
        if emulation and format_info.get('format')=='PE':
            from sentinelav.detection.emulation import emulate
            output=emulate(data,format_info,analyze,self.options.get('emulation_backend','speakeasy'),self.options.get('emulation_profile','background'))
            coverage['emulation']={key:output.get(key) for key in ('status','api_calls','api_attempts','instructions_observed','changed_pages','backend','termination_reason','diagnostics')}
            coverage['emulation']['api_events']=output.get('api_events',[])[:64]
            omissions.extend(output['omissions'])
            events=output.get('api_events',[])
            kinds={event['kind'] for event in events}
            persistence=any(event['kind']=='registry_write' and re.search(
                r'\\currentversion\\(?:run|runonce)(?:\\|$)',event.get('path','').casefold().replace('/','\\')) for event in events)
            if persistence and {'file_write','network_intent'}<=kinds:
                facts.append(Evidence('emulation','modeled_behavior_sequence',
                    'Emulated program writes a virtual file and autorun persistence and attempts a network connection',
                    details=dict(events=events[:32],scope='Modeled API intentions, not observed host effects')))
            for item in output['findings']:
                facts.append(Evidence('emulation','concealed_content','Emulated changed executable page matches detection patterns',confirmed=True,details=item))
        policy=self.assets.get('policy')
        if policy and time.time()>=policy[1]['expires']:omissions.append('Fusion policy expired');policy=None
        result=decide(facts,omissions,policy[0] if policy else None)
        result['coverage']=coverage
        return result
