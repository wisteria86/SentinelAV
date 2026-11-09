# Purpose: Explicit first-time Microsoft Sysmon/ETW setup; never installs on the host.
# Works with: lab.qualification.backends, lab.qualification.store, paths, workspace
# Used by: the Python module loader or CLI entry point

"""Explicit first-time Microsoft Sysmon/ETW setup; never installs on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile
from sentinelav.workspace import Workspace,unlinked
from sentinelav.paths import PROJECT_ROOT
from sentinelav.lab.qualification.backends import powershell,quote
from sentinelav.lab.qualification.store import write_json


SYSMON_CONFIG='''<Sysmon schemaversion="4.90"><HashAlgorithms>SHA256</HashAlgorithms><EventFiltering>
<ProcessCreate onmatch="exclude"/><ProcessTerminate onmatch="exclude"/>
<FileCreate onmatch="exclude"/><FileDeleteDetected onmatch="exclude"/>
<RegistryEvent onmatch="exclude"/><NetworkConnect onmatch="exclude"/>
<DnsQuery onmatch="exclude"/><CreateRemoteThread onmatch="exclude"/>
<ProcessTampering onmatch="exclude"/>
</EventFiltering></Sysmon>'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-sysmon-eula',action='store_true',help='Accept Microsoft Sysinternals terms for disposable lab installations only')
    args=parser.parse_args()
    if not args.accept_sysmon_eula:parser.error('Explicit --accept-sysmon-eula required; review https://learn.microsoft.com/sysinternals/license-terms')
    work=Workspace();root=work.run('lab','telemetry-setup');archive=root/'Sysmon.zip';size=0
    with urllib.request.urlopen('https://download.sysinternals.com/files/Sysmon.zip',timeout=30) as response,archive.open('xb') as output:
        if not response.geturl().startswith('https://download.sysinternals.com/'):raise ValueError('Unexpected Sysmon download source')
        while block:=response.read(1024*1024):
            size+=len(block)
            if size>32*1024*1024:raise ValueError('Sysmon package exceeds bounded download')
            output.write(block)
    sysmon=root/'Sysmon64.exe'
    with zipfile.ZipFile(archive) as z:
        info=z.getinfo('Sysmon64.exe')
        if info.file_size>32*1024*1024:raise ValueError('Sysmon member too large')
        sysmon.write_bytes(z.read(info))
    code="$s=Get-AuthenticodeSignature -LiteralPath "+quote(sysmon)+";if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notlike '*Microsoft*'){exit 1};$s.SignerCertificate.Thumbprint"
    thumbprint=powershell(code).strip()
    destination=root/'Collector'
    powershell('& '+quote(PROJECT_ROOT/'scripts/Build-KernelCollector.ps1')+' -OutputDirectory '+quote(destination),600,log=root/'collector-build.log')
    (root/'sysmon.xml').write_text(SYSMON_CONFIG,encoding='utf-8')
    final=work.area('lab')/'qualification/support'
    if final.exists():raise FileExistsError('Existing reviewed lab support preserved; replace explicitly after review')
    support=final.with_name('support-'+__import__('uuid').uuid4().hex);support.mkdir(parents=True)
    shutil.copyfile(sysmon,support/'Sysmon64.exe');shutil.copyfile(root/'sysmon.xml',support/'sysmon.xml');shutil.copytree(destination,support/'Collector')
    records=[dict(path=p.relative_to(support).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in support.rglob('*') if p.is_file()]
    write_json(support/'manifest.json',dict(schema=1,sysmon_eula_accepted=True,microsoft_signer_thumbprint=thumbprint,
        download='https://download.sysinternals.com/files/Sysmon.zip',archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),files=records))
    support.rename(final)
    print('Guest-only telemetry package staged:',final)


if __name__=='__main__':main()
