# Purpose: Windows response operations: user-scoped encrypted storage and verified identities.
# Works with: detection.inspection, paths, response.containment, response.response_files
# Used by: data.change_journal, entrypoint, lab.qualification.disk_pressure,
#   lab.qualification.evaluation_environment

"""Windows response operations: user-scoped encrypted storage and verified identities."""
from sentinelav.paths import PROJECT_ROOT
import csv
import ctypes
from ctypes import wintypes
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import psutil
from sentinelav.detection.inspection import IsolatedScanner as Scanner


from .response_files import digest, checked_path, Blob, dpapi, locked_file, delete_locked, is_critical_process


class ResponseService:
    def __init__(self,store,root):
        self.store,self.root = store,Path(root)
        self.vault = store.path.parent/'quarantine'

    def audit(self,kind,details,level='Info',**extra):
        self.store.save_event(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'),kind=kind,
                                   details=details,source='Response',level=level,**extra))

    def plan_process_tree(self,pid,creation):
        from sentinelav.response.containment import plan_tree
        plan=plan_tree(pid,creation)
        self.audit('Process-tree plan created',f"PID {pid}; {len(plan['processes'])} eligible processes")
        return dict(state='Plan ready',process_tree_plan=plan)

    def respond_process_tree(self,plan,approved_hashes):
        from sentinelav.response.containment import execute_plan
        result=execute_plan(self,plan,approved_hashes)
        return dict(state='Completed' if result['complete'] else 'Partial — review per-process results',process_tree_result=result)

    def secure_vault(self):
        if self.vault.is_symlink() or self.vault.is_junction():
            raise ValueError('Quarantine path must not be a link')
        self.vault.mkdir(exist_ok=True)
        for p in self.vault.parents:
            if p.is_symlink() or p.is_junction():
                raise ValueError('Quarantine parent must not be a link')
        result = subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,text=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        sid = next(csv.reader(io.StringIO(result.stdout.strip())))[1]
        if not sid.startswith('S-1-'):
            raise RuntimeError('Unable to identify quarantine owner')
        subprocess.run(['icacls',str(self.vault),'/inheritance:r','/grant:r',f'*{sid}:(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],
                       capture_output=True,text=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)

    def quarantine_file(self,detection):
        path = checked_path(detection['path'])
        if not path.is_file():
            raise ValueError('Detected file no longer exists')
        scanner = Scanner(self.root/'signatures.json',self.root/'rules',self.store.get('max_mb',100),self.store.get('exclusions',[]),self.store.get('trusted_hashes',[]),options=self.store.get('inspection_options',{}))
        result = scanner.scan([path],lambda:False,lambda *args:None)
        verified = next((d for d in result['detections'] if d['sha256']==detection['sha256']),None)
        if verified is None:
            raise ValueError('File changed, is excluded, or no longer matches a signature/rule; scan it again')
        if detection.get('fusion_policy_id') and (not verified.get('automatic_response_eligible') or verified.get('fusion_policy_id')!=detection['fusion_policy_id']):
            raise ValueError('Calibrated response policy no longer verifies; action requires renewed review')
        self.secure_vault()
        record = dict(id=uuid.uuid4().hex,original=str(path),sha256=detection['sha256'],
                      reasons=verified['reasons'],date=time.strftime('%Y-%m-%d %H:%M:%S'),state='Preparing')
        blob_path = self.vault/(record['id']+'.sav')
        self.audit('Quarantine requested',str(path),path=str(path))
        with locked_file(path) as stream:
            if os.fstat(stream.fileno()).st_nlink != 1:
                raise ValueError('Hard-linked files cannot be quarantined safely')
            data = stream.read(scanner.max_bytes+1)
            if len(data)>scanner.max_bytes or digest(data)!=record['sha256']:
                raise ValueError('File changed before quarantine; scan it again')
            record['size'] = len(data)
            self.store.save_quarantine(record)
            encrypted = dpapi(data)
            with blob_path.open('xb') as output:
                output.write(encrypted)
                output.flush()
                os.fsync(output.fileno())
            if digest(dpapi(blob_path.read_bytes(),decrypt=True)) != record['sha256']:
                raise ValueError('Encrypted quarantine verification failed; original preserved')
            delete_locked(stream)
        record['state'] = 'Quarantined'
        self.store.save_quarantine(record)
        self.audit('File quarantined',str(path),path=str(path),quarantine_id=record['id'])
        return record

    def record(self,identity):
        if len(identity)!=32 or any(c not in '0123456789abcdef' for c in identity):
            raise ValueError('Invalid quarantine identity')
        record = next((r for r in self.store.quarantine() if r['id']==identity),None)
        if record is None or record['state'] not in ('Preparing','Quarantined','Restore pending','Delete pending'):
            raise ValueError('Quarantine item is not available for this action')
        self.secure_vault()
        blob = self.vault/(identity+'.sav')
        if blob.is_symlink() or blob.is_junction():
            raise ValueError('Linked quarantine objects are not permitted')
        if blob.exists() and blob.stat().st_size > record.get('size',100*1024*1024)+1024*1024:
            raise ValueError('Quarantine object exceeds its expected size')
        return record,blob

    def restore(self,identity,destination):
        record,blob = self.record(identity)
        target = checked_path(destination)
        if target.exists():
            raise FileExistsError('Restore never overwrites an existing file; choose another path')
        if not target.parent.is_dir():
            raise ValueError('Restore folder does not exist')
        content = dpapi(blob.read_bytes(),decrypt=True)
        if digest(content)!=record['sha256']:
            raise ValueError('Quarantine integrity check failed; restore refused')
        record.update(state='Restore pending',restore_path=str(target))
        self.store.save_quarantine(record)
        self.audit('Restore requested',str(target),quarantine_id=identity)
        with locked_file(target,create=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            if digest(stream.read())!=record['sha256']:
                raise ValueError('Restore verification failed; encrypted copy retained')
            blob.unlink()
        record['state']='Restored'
        self.store.save_quarantine(record)
        self.audit('File restored',str(target),path=str(target),quarantine_id=identity)
        return record

    def recover(self,identity):
        record,blob = self.record(identity)
        if record['state']=='Preparing':
            if Path(record['original']).exists():
                raise ValueError('Original still exists; encrypted backup was retained. Restore to another path or delete the encrypted copy.')
            if digest(dpapi(blob.read_bytes(),True))!=record['sha256']:
                raise ValueError('Recovery integrity check failed')
            record['state']='Quarantined'
        elif record['state']=='Restore pending':
            target = checked_path(record['restore_path'])
            if not target.is_file():
                raise ValueError('Restored destination is absent or incomplete. Encrypted copy retained; choose Restore to another destination.')
            with locked_file(target) as stream:
                if digest(stream.read())!=record['sha256']:
                    raise ValueError('Restored destination is incomplete; encrypted copy retained')
                blob.unlink(missing_ok=True)
            record['state']='Restored'
        elif record['state']=='Delete pending':
            return self.delete(identity)
        self.store.save_quarantine(record)
        self.audit('Interrupted response reconciled',identity,quarantine_id=identity)
        return record

    def delete(self,identity):
        record,blob = self.record(identity)
        record['state']='Delete pending'
        self.store.save_quarantine(record)
        self.audit('Permanent deletion requested',identity,quarantine_id=identity)
        blob.unlink(missing_ok=True)
        record['state']='Deleted'
        self.store.save_quarantine(record)
        self.audit('Quarantine file deleted',identity,quarantine_id=identity)
        return record

    def terminate(self,pid,created,detection):
        if pid in (0,4,os.getpid(),os.getppid()):
            raise ValueError('System, SentinelAV, and parent processes cannot be terminated')
        path = checked_path(detection['path'])
        result = Scanner(self.root/'signatures.json',self.root/'rules',self.store.get('max_mb',100),self.store.get('exclusions',[]),self.store.get('trusted_hashes',[]),options=self.store.get('inspection_options',{})).scan([path],lambda:False,lambda *args:None)
        if not any(d['sha256']==detection['sha256'] for d in result['detections']):
            raise ValueError('Fresh signature detection is required; behavior alone is insufficient')
        process = psutil.Process(pid)
        if process.create_time()!=created or Path(process.exe()).resolve()!=path:
            raise ValueError('Process identity changed; termination refused')
        ancestors = {p.pid for p in psutil.Process().parents()}
        if pid in ancestors:
            raise ValueError('SentinelAV ancestor processes cannot be terminated')
        if process.username()!=psutil.Process().username():
            raise ValueError('Only processes owned by the current Windows user may be terminated')
        if is_critical_process(pid):
            raise ValueError('Windows critical processes cannot be terminated')
        self.audit('Process termination requested',f'PID {pid}: {path}',pid=pid,path=str(path))
        process.terminate()
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            self.audit('Termination not confirmed',f'PID {pid} is still running','Warning',pid=pid)
            raise RuntimeError('Process has not exited; no forced kill was attempted')
        self.audit('Process terminated',f'PID {pid}: {path}',pid=pid,path=str(path))
        return dict(pid=pid,state='Terminated')
