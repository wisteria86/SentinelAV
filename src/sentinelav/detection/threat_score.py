# Purpose: Turn layer-tagged evidence into an explainable threat score, verdict and confidence.
# Works with: detection.indicators, detection.file_analysis
# Used by: detection.file_analysis, response.auto_response, lab.qualification.zoo_guest

"""Turn layer-tagged evidence into an explainable threat score, verdict and confidence.

Correlated indicators share a group whose contribution is capped, so one weak
trait cannot reach Malicious and one property is never counted twice. Only
exact-identity evidence (hash, family rule, test marker) is decisive.
"""
MALICIOUS=70
SUSPICIOUS=35
AUTOMATIC_SCORE=85
TRUST_DAMPING=.35
DECISIVE_LAYERS={'hash','family_yara','test_marker','amsi','fusion','derived_signature','clamav_signature','hash_md5','pack_family'}
DAMPED_LAYERS={'heuristic','generic_yara','ml','clamav_heuristic'}
# A ClamAV signature on a validly signed file is more likely a false positive than stolen-certificate malware.
TRUSTED_CLAMAV_WEIGHT=60
# Installers and DRM pack legitimately, so packing alone stays below Suspicious and only supports other evidence.
GROUP_CAPS={'packing':28,'structure':30,'ml':65,'context':10,'obfuscation':25,'generic_yara':45,'destruction':70,
    'ransomware':60,'replication':55,'clamav_heuristic':45,'clamav':60,'yara_pack':45,'certificate':60,'boot_residency':50,'boot_hook':40}
DEFAULT_CAP=45
# Evaluation arms re-score the same evidence: A full product, B generalized, C without learned models.
ARMS={'full':None,'generalized':{'heuristic','generic_yara','ml','context','clamav_heuristic'},
    'heuristic':{'heuristic','generic_yara','context','clamav_heuristic'}}


def indicator(code,group,weight,explanation,layer='heuristic',category='',evidence=''):
    return dict(code=code,group=group,weight=int(weight),explanation=str(explanation)[:300],layer=layer,
        category=category,evidence=str(evidence)[:160])


def _groups(items,trusted):
    totals={}
    for item in items:
        value=item['weight']*(TRUST_DAMPING if trusted and item['layer'] in DAMPED_LAYERS else 1)
        totals[item['group']]=totals.get(item['group'],0)+value
    return {group:min(value,GROUP_CAPS.get(group,DEFAULT_CAP)*(TRUST_DAMPING if trusted else 1)) for group,value in totals.items()}


def verdict_for(score):
    return 'Malicious' if score>=MALICIOUS else 'Suspicious' if score>=SUSPICIOUS else 'Clean'


def _confidence(score,groups,decisive,partial):
    if decisive:return 'High'
    independent=sum(value>=12 and group!='context' for group,value in groups.items())
    level=2 if independent>=3 and score>=MALICIOUS else 1 if independent>=2 else 0
    if partial and level:level-=1
    return ('Low','Medium','High')[level]


def _threat_name(items,platform,decisive):
    if decisive:
        first=decisive[0]
        return first.get('threat') or first['explanation'][:80]
    ranked=sorted((i for i in items if i.get('category')),key=lambda i:-i['weight'])
    return f"Heuristic.{platform or 'Generic'}.{ranked[0]['category'] if ranked else 'Generic'}"


def score(items,platform='Generic',trusted=False,partial=False):
    """Pure function of its evidence, so evaluation arms and repeat scans reproduce it."""
    if trusted:
        # Broad third-party identities (ClamAV, MD5 lists) on a validly signed file go to a person instead of deciding.
        # MD5 lists include signed system files, so on a signed file they carry no weight at all.
        items=[dict(i,layer='clamav_trusted',group='clamav',weight=TRUSTED_CLAMAV_WEIGHT) if i['layer'] in ('clamav_signature','pack_family') else i
            for i in items if i['layer']!='hash_md5']
    decisive=[i for i in items if i['layer'] in DECISIVE_LAYERS]
    groups=_groups(items,trusted)
    if 'clamav' in groups:groups['clamav']=TRUSTED_CLAMAV_WEIGHT
    value=100 if decisive else min(99,round(sum(groups.values())))
    # Valid signers ship unusual but legitimate code. Only a learned model or a ClamAV signature keeps a signed file above Clean.
    if trusted and not decisive and 'ml' not in groups and 'clamav' not in groups:value=min(value,SUSPICIOUS-1)
    ordered=sorted(items,key=lambda i:(i['layer'] not in DECISIVE_LAYERS,-i['weight']))
    return dict(score=value,verdict=verdict_for(value),confidence=_confidence(value,groups,decisive,partial),
        threat_name=_threat_name(items,platform,decisive),trusted_signature=bool(trusted),
        groups={k:round(v,1) for k,v in sorted(groups.items())},indicators=ordered[:24],
        reasons=[i['explanation'] for i in ordered[:12]])


def arm_scores(items,platform='Generic',trusted=False,partial=False):
    result={}
    for name,layers in ARMS.items():
        chosen=items if layers is None else [i for i in items if i['layer'] in layers]
        assessed=score(chosen,platform,trusted,partial)
        result[name]=dict(score=assessed['score'],verdict=assessed['verdict'],confidence=assessed['confidence'])
    return result


def automatic_eligible(assessment):
    """The agreed policy: high-confidence only, and a valid trusted signature always defers to a person."""
    if assessment.get('trusted_signature') and assessment.get('score',0)<100:return False
    return assessment.get('verdict')=='Malicious' and assessment.get('score',0)>=AUTOMATIC_SCORE and assessment.get('confidence')=='High'
