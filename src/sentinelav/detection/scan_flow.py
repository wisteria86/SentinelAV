# Purpose: Walk scan roots and assemble bounded per-file analysis results.
# Works with: data.contracts, detection.archive_inspection, detection.decisions, detection.file_formats,
#   platform.amsi_client
# Used by: detection.engine

"""Read-only detection engine, independent of Qt. Never executes inspected files."""
import hashlib
import os
import time
from pathlib import Path
from sentinelav.detection.archive_inspection import inspect_zip


class ScanFlowMixin:
    def scan(self, roots, cancelled, progress):
        result = dict(started=time.strftime('%Y-%m-%d %H:%M:%S'), scanned=0,
                      skipped=0, errors=[], detections=[], status='Complete', elapsed=0,
                      structural_review=[],structural_review_total=0,advanced_reviews=[],advanced_review_total=0)
        start = time.monotonic()
        self.current_scan_result=result
        seen = set()
        capture_identity=len(roots)==1 and Path(roots[0]).is_file()
        if not roots:
            result['errors'].append('No scan locations were selected or available')

        def walk(root):
            if root.is_symlink() or root.is_junction():
                result['errors'].append(f'Linked scan root was not followed: {root}')
                return
            if self.excluded(root):
                return
            if root.is_file():
                yield root
            elif root.is_dir():
                def onerror(error):
                    result['errors'].append(str(error))
                for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
                    if cancelled():
                        return
                    dirs[:] = [d for d in dirs if not (Path(directory)/d).is_symlink()
                               and not (Path(directory)/d).is_junction()
                               and not self.excluded(Path(directory)/d)]
                    for name in files:
                        yield Path(directory)/name
            else:
                result['errors'].append(f'Unavailable path: {root}')

        for root in roots:
            for path in walk(Path(root)):
                if cancelled():
                    break
                try:
                    resolved = path.resolve()
                    if resolved in seen or path.is_symlink() or self.excluded(path):
                        continue
                    seen.add(resolved)
                    self.current_parent=str(resolved);self.member_seen=set();self.member_bytes=0
                    if path.stat().st_size > self.max_bytes:
                        result['skipped'] += 1
                        continue
                    digest = hashlib.sha256()
                    data = bytearray()
                    with path.open('rb') as stream:
                        initial=os.fstat(stream.fileno())
                        while chunk := stream.read(1024 * 1024):
                            if cancelled():
                                break
                            data.extend(chunk)
                            if len(data) > self.max_bytes:
                                raise ValueError('File grew beyond size limit')
                            digest.update(chunk)
                        final=os.fstat(stream.fileno())
                    if cancelled():
                        break
                    current=path.stat()
                    # Windows fstat/stat disagree about ctime on rewritten files;
                    # compare ctime only within the same descriptor API.
                    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
                    if identity(initial)!=identity(final) or identity(initial)!=identity(current) or initial.st_ctime_ns!=final.st_ctime_ns or len(data)!=initial.st_size:
                        raise ValueError('File changed during inspection; scan it again')
                    sha = digest.hexdigest()
                    self.current_parent_sha=sha
                    if capture_identity:
                        result['file_identity']=dict(path=str(resolved),sha256=sha,stat=[str(value) for value in identity(current)])
                    if sha in self.trusted_hashes:
                        result['scanned'] += 1
                        continue
                    # Preserve an independently verified exact-hash finding
                    # even if a subsequent native parser fails in the worker.
                    early_label=self.signatures.get(sha)
                    if early_label is not None and getattr(self,'early_finding',None):
                        self.early_finding(dict(path=str(resolved),sha256=sha,reasons=['SHA-256: '+early_label],yara_matches=[]))
                    names,yara_matches,inspection_errors=self.analyze_bytes(data,sha)
                    analysis=format_info=None
                    result['errors'].extend(f'{path}: {error}' for error in inspection_errors)
                    try:
                        from sentinelav.detection.file_formats import pe_metadata,static_analysis
                        format_info=pe_metadata(data)
                        analysis=static_analysis(data,format_info)
                        if analysis['imports']['status'] in ('Incomplete','Unavailable'):
                            result['errors'].append(f"{path}: PE import inspection: {analysis['imports'].get('reason','Unavailable')}")
                        if analysis['delay_imports']['status']=='Incomplete':
                            result['errors'].append(f"{path}: PE delay imports: {analysis['delay_imports']['reason']}")
                        for omission in analysis.get('image_details',{}).get('omissions',[]):result['errors'].append(f'{path}: PE details: '+omission)
                        if capture_identity:
                            result['file_format']=format_info
                            result['static_analysis']=analysis
                        if analysis['signals']:
                            result['structural_review_total']+=1
                            # Bound worker transport for folder scans. These are
                            # review signals, never signature detections.
                            if len(result['structural_review'])<100:
                                result['structural_review'].append(dict(path=str(resolved),sha256=sha,
                                    **{k:v for k,v in analysis.items() if k not in ('imports','delay_imports')}))
                    except ValueError as error: result['errors'].append(f'{path}: PE metadata inspection: {error}')
                    if self.options['amsi'] and path.suffix.lower() in ('.ps1','.psm1','.js','.vbs','.hta'):
                        try:
                            from sentinelav.platform.amsi_client import scan_buffer
                            amsi=scan_buffer(bytes(data),path.name)
                            if amsi['detected'] or amsi['blocked_by_policy']: names.append('AMSI: installed provider detection/policy block')
                        except Exception as error: result['errors'].append(f'{path}: AMSI unavailable: {error}')
                    result['scanned'] += 1
                    if names:
                        result['detections'].append(dict(path=str(resolved), sha256=sha, reasons=names,yara_matches=yara_matches))
                    if self.advanced and analysis is not None:
                        decision=self.advanced.inspect(data,path,sha,analysis,format_info,self.analyze_member,cancelled,
                                                       emulation=self.options['emulation'])
                        if capture_identity: result['advanced_analysis']=decision
                        derived=[e for e in decision['evidence'] if e.get('confirmed')]
                        if derived:
                            reasons=[]
                            for item in derived:
                                reasons.extend('Analyzed content ('+item['source']+'): '+reason for reason in item.get('details',{}).get('reasons',[]))
                            if reasons:
                                result['detections'].append(dict(path=str(resolved),sha256=sha,reasons=reasons,
                                    yara_matches=[],analysis_evidence=derived,detection_scope='derived content',
                                    automatic_response_eligible=decision.get('automatic_response_eligible',False),fusion_policy_id=decision.get('fusion_policy_id')))
                        if decision['verdict']=='Review':
                            result['advanced_review_total']+=1
                            if len(result['advanced_reviews'])<50:
                                result['advanced_reviews'].append(dict(path=str(resolved),sha256=sha,
                                    reasons=[e['description'] for e in decision['evidence'][:16]],
                                    omissions=decision['omissions'][:8],automatic_response_eligible=False))
                        if decision['omissions']:
                            result['errors'].append(f'{path}: Advanced analysis omissions: '+ '; '.join(decision['omissions'])[:1200])
                    if self.options['archives']:
                        nested,omissions,archive_stats=inspect_zip(bytes(data),self.analyze_member,cancelled)
                        result['archive_entries_seen']=result.get('archive_entries_seen',0)+archive_stats['entries']
                        result['archive_bytes_expanded']=result.get('archive_bytes_expanded',0)+archive_stats['expanded']
                        result['errors'].extend(f'{path}: {error}' for error in omissions)
                        for finding in nested:
                            result['detections'].append(dict(path=str(resolved),sha256=sha,
                                reasons=['Archive member: '+'!/'.join(finding['member_chain'])+' — '+reason for reason in finding['reasons']],
                                **{key:value for key,value in finding.items() if key!='reasons'}))
                        if data.startswith((b'Rar!\x1a\x07',b'7z\xbc\xaf\x27\x1c')):
                            result['errors'].append(f'{path}: Unsupported archive format; members were not inspected')
                except Exception as error:
                    result['errors'].append(f'{path}: {error}')
                progress(str(path), result['scanned'], len(result['detections']))
            if cancelled():
                break
        result['status'] = 'Cancelled' if cancelled() else ('Complete with omissions' if result['errors'] or result['skipped'] else 'Complete')
        result['elapsed'] = round(time.monotonic() - start, 2)
        if capture_identity:
            from sentinelav.detection.decisions import Evidence,decide
            facts=[]
            for finding in result['detections']:
                if finding.get('detection_scope')=='derived content': continue
                for reason in finding['reasons']:
                    source='hash' if 'SHA-256: ' in reason else 'yara' if 'YARA: ' in reason else 'amsi' if 'AMSI: ' in reason else 'eicar'
                    facts.append(Evidence(source,'signature_match',reason,confirmed=True))
            facts.extend(Evidence('static',s['code'],s['explanation']) for s in result.get('static_analysis',{}).get('signals',[]))
            facts.extend(Evidence(**item) for item in result.get('advanced_analysis',{}).get('evidence',[]))
            result['decision']=decide(facts,result['errors'])
        result['warnings'] = self.warnings
        result['yara'] = self.rule_summary
        result['signature_policy']=dict(signature_free=self.options['signature_free'],hashes=not self.options['signature_free'],
            yara=not self.options['signature_free'],test_markers=not self.options['signature_free'],
            amsi=self.options['amsi'],reputation=self.options['reputation'])
        from sentinelav.data.contracts import analysis_result
        result['analysis_result']=analysis_result(result,self.options,dict(engine='0.16.0',
            signatures=self.signatures.metadata,yara=self.rule_summary))
        return result
