"""Read-only detection engine, independent of Qt. Never executes inspected files."""
import hashlib
import json
import os
import time
from pathlib import Path
from sentinelav.detection.signature_db import SignatureIndex
from sentinelav.detection.yara_rules import compile_rules,evidence
from sentinelav.detection.archive_inspection import inspect_zip


class Scanner:
    def __init__(self, signatures, rules_dir, max_mb=100, exclusions=(), trusted_hashes=(),options=None):
        self.signatures = SignatureIndex(signatures)
        self.max_bytes = max_mb * 1024 * 1024
        self.exclusions = [Path(p).resolve() for p in exclusions]
        self.trusted_hashes = set(trusted_hashes)
        self.rules,self.rule_summary,self.rule_metadata = compile_rules(rules_dir)
        self.warnings = list(self.rule_summary['warnings'])
        self.options=dict(archives=(options or {}).get('archives',True),amsi=(options or {}).get('amsi',False))

    def analyze_bytes(self,data,sha=None):
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

    def scan(self, roots, cancelled, progress):
        result = dict(started=time.strftime('%Y-%m-%d %H:%M:%S'), scanned=0,
                      skipped=0, errors=[], detections=[], status='Complete', elapsed=0)
        start = time.monotonic()
        self.current_scan_result=result
        seen = set()
        capture_identity=len(roots)==1 and Path(roots[0]).is_file()

        def walk(root):
            if root.is_symlink() or self.excluded(root):
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
                    result['errors'].extend(f'{path}: {error}' for error in inspection_errors)
                    try:
                        from sentinelav.detection.file_formats import pe_metadata
                        format_info=pe_metadata(data)
                        if capture_identity: result['file_format']=format_info
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
                    if self.options['archives']:
                        nested,omissions,archive_stats=inspect_zip(bytes(data),self.analyze_bytes,cancelled)
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
        result['warnings'] = self.warnings
        result['yara'] = self.rule_summary
        return result
