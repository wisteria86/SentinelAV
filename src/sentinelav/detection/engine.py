# Purpose: Read-only detection engine, independent of Qt. Never executes inspected files.
# Works with: detection.advanced_pipeline, detection.archive_inspection, detection.file_formats,
#   detection.scan_flow, detection.signature_db
# Used by: detection.inspection_worker, entrypoint, lab.lab, tests.unit.test_amsi_buffers

"""Read-only detection engine, independent of Qt. Never executes inspected files."""
import hashlib
import json
import os
import time
from pathlib import Path
from sentinelav.detection.signature_db import SignatureIndex
from sentinelav.detection.yara_rules import compile_rules,evidence
from sentinelav.detection.archive_inspection import inspect_zip


class DisabledSignatures:
    metadata=dict(status='Disabled',reason='Signature-free evaluation',count=0)
    def __len__(self):return 0
    def get(self,sha):return None
    def close(self):pass


from .scan_flow import ScanFlowMixin

class Scanner(ScanFlowMixin):
    def __init__(self, signatures, rules_dir, max_mb=100, exclusions=(), trusted_hashes=(),options=None):
        from sentinelav.platform.engine_policy import inspection_options
        self.options=inspection_options(options)
        strict=self.options['signature_free']
        self.signatures = DisabledSignatures() if strict else SignatureIndex(signatures)
        self.max_bytes = max_mb * 1024 * 1024
        self.exclusions = [Path(p).resolve() for p in exclusions]
        self.trusted_hashes = set() if strict else set(trusted_hashes)
        if strict:self.rules,self.rule_summary,self.rule_metadata=None,dict(status='Disabled',warnings=[],reason='Signature-free evaluation'),{}
        else:self.rules,self.rule_summary,self.rule_metadata = compile_rules(rules_dir)
        self.warnings = list(self.rule_summary['warnings'])
        self.advanced=None
        if self.options['advanced']:
            from sentinelav.detection.advanced_pipeline import AdvancedPipeline
            self.advanced=AdvancedPipeline(self.options.get('analysis_store'),self.options)

    def analyze_bytes(self,data,sha=None):
        if self.options['signature_free']:return [],[],[]
        sha=sha or hashlib.sha256(data).hexdigest()
        if sha in self.trusted_hashes: return [],[],[]
        names=[]
        matches=[]
        errors=[]
        label=self.signatures.get(sha)
        if label is not None: names.append('SHA-256: '+label)
        eicar=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        if eicar in data: names.append('EICAR test file (not malware)')
        if self.rules:
            try:
                for match in self.rules.match(data=bytes(data),timeout=5):
                    names.append('YARA: '+match.rule)
                    matches.append(evidence(match,self.rule_metadata))
            except Exception as error: errors.append('YARA inspection failed: '+str(error))
        return names,matches,errors

    def excluded(self, path):
        resolved = path.resolve()
        return any(resolved == p or p in resolved.parents for p in self.exclusions)

    def analyze_member(self,data,sha=None):
        reasons,matches,errors=self.analyze_bytes(data,sha)
        if self.advanced and data.startswith(b'MZ') and (self.options['model'] or self.options['neural']):
            digest=sha or hashlib.sha256(data).hexdigest()
            if digest not in self.member_seen:
                self.member_seen.add(digest)
                if len(self.member_seen)>50 or len(data)>8*1024*1024 or self.member_bytes+len(data)>32*1024*1024:
                    errors.append('Embedded learned-analysis budget reached')
                else:
                    self.member_bytes+=len(data)
                    try:
                        from sentinelav.detection.file_formats import pe_metadata,static_analysis
                        metadata=pe_metadata(data)
                        decision=self.advanced.inspect(data,Path('decoded.exe'),digest,static_analysis(data,metadata),metadata,self.analyze_bytes,lambda:False)
                        self.current_scan_result.setdefault('embedded_model_analysis',[]).append(dict(
                            parent_path=self.current_parent,member_sha256=digest,bytes=len(data),coverage=decision['coverage'],
                            verdict=decision['verdict'],omissions=decision['omissions'],automatic_response_eligible=False,
                            scope='Extracted or virtual bytes; no physical-file response authority'))
                        errors.extend(decision['omissions'])
                        if decision['verdict']=='Review':
                            self.current_scan_result['advanced_review_total']+=1
                            if len(self.current_scan_result['advanced_reviews'])<50:
                                self.current_scan_result['advanced_reviews'].append(dict(path=self.current_parent,sha256=self.current_parent_sha,
                                    member_sha256=digest,reasons=['Extracted bytes: '+item['description'] for item in decision['evidence'][:16]],
                                    omissions=decision['omissions'][:8],automatic_response_eligible=False))
                    except Exception as error:errors.append('Embedded model inspection unavailable: '+str(error)[:200])
        return reasons,matches,errors
