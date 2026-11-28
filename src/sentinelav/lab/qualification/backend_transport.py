# Purpose: Install guest telemetry and exchange typed jobs and bounded results.
# Works with: lab.qualification.backend_control, lab.qualification.contracts, lab.qualification.reporting,
#   lab.qualification.store
# Used by: lab.qualification.backend_sandbox

"""Owned guest lifecycle and bounded metadata transport. No writable host share."""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import time
import uuid
from .contracts import identifier
from .store import write_json
from .backend_control import run, quote, read_export, Blocked

FRAME_WORKERS = 16


class GuestTransportMixin:
    """Moves small pieces of data into and out of an evaluation guest without any writable shared
    folder.

    Data goes in as tiny Base64 chunks written by guest commands. Results come out through exit
    codes only: each command reports three bytes of the export file as its exit status, and the host
    stitches them back together. Slow, but strictly one-way and bounded.
    """

    def setup_telemetry(self):
        """Install Sysmon (after checking its Microsoft signature) and the telemetry collector inside
        the guest, and fail clearly if any step does not succeed.
        """
        code = r'''$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$log='C:\SentinelAV-Test\TelemetrySetup'
New-Item $log -ItemType Directory -Force|Out-Null
$result=@{schema=1;succeeded=$false;stage='validate-source'}
$code=1
try {
$src='C:\SentinelAV-Input\LabSupport'
if(!(Test-Path "$src\Sysmon64.exe") -or !(Test-Path "$src\Collector\SentinelAV.Telemetry.exe")){throw 'Approved telemetry support files missing'}
$result.stage='verify-signature'
$sig=Get-AuthenticodeSignature "$src\Sysmon64.exe"
$result.signature_status=[string]$sig.Status
if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Microsoft*'){throw 'Guest Microsoft signature verification failed'}
$result.stage='copy-collector'
$dst="$env:ProgramFiles\SentinelAV-Lab-Collector"
if(Test-Path $dst){throw 'Existing collector directory preserved; fresh guest required'}
New-Item $dst -ItemType Directory|Out-Null
& icacls.exe $dst '/inheritance:r' '/grant:r' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Protected collector ACL setup failed'}
Copy-Item "$src\Collector\*" $dst -Recurse
& icacls.exe $dst '/setowner' '*S-1-5-18' '/T'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Protected collector ownership setup failed'}
$result.stage='install-sysmon'
# Sysmon writes its normal banner to stderr. Do not turn that into a
# terminating PowerShell NativeCommandError under ErrorActionPreference Stop.
$p=Start-Process -FilePath "$src\Sysmon64.exe" -ArgumentList @('-accepteula','-i',"$src\sysmon.xml") -WindowStyle Hidden -PassThru -RedirectStandardOutput "$log\stdout.txt" -RedirectStandardError "$log\stderr.txt"
$handle=$p.Handle
if(!$p.WaitForExit(45000)){$p.Kill();throw 'Owned Sysmon installer timed out'}
if($null -eq $p.ExitCode){throw 'Sysmon installer exit code unavailable'}
$result.sysmon_exit_code=$p.ExitCode
if($p.ExitCode -ne 0){throw 'Sysmon installer failed'}
if((Get-Service -Name Sysmon64 -ErrorAction Stop).Status -ne 'Running'){throw 'Guest Sysmon service is not running'}
$result.stage='complete';$result.succeeded=$true;$code=0
} catch {
    $result.error=([string]$_.Exception.Message).Substring(0,[Math]::Min(800,([string]$_.Exception.Message).Length))
    foreach($name in @('stdout','stderr')) {
        if(Test-Path "$log\$name.txt"){$text=[IO.File]::ReadAllText("$log\$name.txt");$result[$name]=$text.Substring(0,[Math]::Min(800,$text.Length))}
    }
} finally {
    [IO.File]::WriteAllText("$log\result.json",($result|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
}
exit $code
'''
        value = self.exec(code, 90, True)
        details = self.read_metadata(
            'C:/SentinelAV-Test/TelemetrySetup/result.json', compressed=False
        )
        from .reporting import redact

        write_json(self.attempt / 'telemetry-setup.json', redact(details))
        if value or details.get('succeeded') is not True:
            raise Blocked(
                'Guest telemetry setup failed at '
                + str(details.get('stage'))
                + ': '
                + str(details.get('error', 'No diagnostic supplied'))
            )

    def execute(self, context):
        """Send one evaluation job into the guest, run SentinelAV on it there, and read back its
        bounded result export.
        """
        nonce = identifier(context['nonce'])
        raw = base64.b64encode(json.dumps(context).encode()).decode()
        jobpath = 'C:/SentinelAV-Test/Jobs/' + nonce + '.json'
        if len(raw) > 1400000:
            raise ValueError('Guest job metadata too large')
        if self.exec(
            "New-Item 'C:/SentinelAV-Test/Jobs' -ItemType Directory -Force|Out-Null;[IO.File]::WriteAllBytes("
            + quote(jobpath)
            + ",[byte[]]@());exit 0"
        ):
            raise RuntimeError('Guest job initialization failed')
        decoded = base64.b64decode(raw)
        for offset in range(0, len(decoded), 4096):
            part = base64.b64encode(decoded[offset : offset + 4096]).decode()
            if self.exec(
                "$f=[IO.File]::Open("
                + quote(jobpath)
                + ",[IO.FileMode]::Append);try{$b=[Convert]::FromBase64String('"
                + part
                + "');$f.Write($b,0,$b.Length)}finally{$f.Dispose()};exit 0"
            ):
                raise RuntimeError('Guest job transport failed')
        # PowerShell's call operator can return before a GUI-subsystem binary.
        # Wait for this exact owned process, not for unrelated guest services.
        code = (
            "$ErrorActionPreference='Stop';$p=Start-Process -FilePath 'C:/SentinelAV-Test/App/SentinelAV.exe' -ArgumentList @('--qualification-job',"
            + quote(jobpath)
            + ") -WindowStyle Hidden -PassThru;$h=$p.Handle;$p.WaitForExit();if($null -eq $p.ExitCode){exit 125};exit $p.ExitCode"
        )
        value = self.exec(code, context['case']['seconds'] + 420)
        failure = value
        write_json(
            self.attempt / ('execution-' + nonce + '.json'),
            dict(case_id=context['case']['id'], nonce=nonce, exit_code=value),
        )
        if self.exec(
            "if(Test-Path "
            + quote('C:/SentinelAV-Test/Qualification/' + nonce + '/export.bin')
            + "){exit 0};exit 77"
        ):
            raise RuntimeError(
                'Guest job exited ' + str(value) + ' without a bounded diagnostic export'
            )
        result = self.read_metadata('C:/SentinelAV-Test/Qualification/' + nonce + '/export.bin')
        if failure:
            write_json(self.attempt / 'guest-error.json', result)
            reason = (
                str(result.get('error', 'Guest error'))
                + ': '
                + str(result.get('reason', 'No diagnostic supplied'))
            )
            if failure == 72:
                raise Blocked(reason)
            raise RuntimeError(reason)
        return result

    def read_metadata(self, path, compressed=True):
        """Read an approved evidence file from the guest, three bytes at a time through exit codes,
        using the fastest available channel. Returns the decoded JSON.
        """
        import re

        if not re.fullmatch(
            r'C:/SentinelAV-Test/(?:Qualification/[a-zA-Z0-9_.-]{1,100}/export\.bin|TelemetrySetup/result\.json)',
            path,
        ):
            raise ValueError('Guest metadata path is not an approved evidence location')
        maximum = 512 * 1024 if compressed else 8192
        prefix = (
            "$ErrorActionPreference='Stop';$p="
            + quote(path)
            + ";$b=[IO.File]::ReadAllBytes($p);if($b.Length -gt "
            + str(maximum)
            + "){exit 81};"
        )
        token = 'setup' if path.endswith('/TelemetrySetup/result.json') else path.split('/')[-2]
        native = False
        size = -1
        if self.owner and self.owner.get('backend') == 'sandbox':
            try:
                size = self.metadata_frame(token, -1) - 1073741824
                native = 0 < size <= maximum
            except (RuntimeError, OSError):
                pass
        if not native:
            size = self.exec(prefix + 'exit (1073741824+$b.Length)') - 1073741824
        if not 0 < size <= maximum:
            raise ValueError('Invalid bounded export size')
        framed = False
        if compressed and not native and self.owner and self.owner.get('backend') == 'sandbox':
            framed = self.prepare_frames(path, token)
        self.progress(
            'Reading bounded guest evidence: '
            + str(size)
            + ' bytes ('
            + ('native' if native else 'batch-frame' if framed else 'PowerShell')
            + ' transport)'
        )
        began = time.monotonic()

        def word(offset):
            """Read three bytes at `offset` from the guest file as one exit code."""
            if self.cancelled() or time.monotonic() - began > 3600:
                raise InterruptedError('Metadata export cancelled/timed out')
            code = (
                prefix
                + '$v=0;for($i=0;$i -lt 3;$i++){if(('
                + str(offset)
                + '+$i) -lt $b.Length){$v=$v -bor ([int]$b[('
                + str(offset)
                + '+$i)] -shl (8*$i))}};exit (1073741824+$v)'
            )
            if framed:
                try:
                    v = self.batch_frame(token, offset) - 1073741824
                except (RuntimeError, OSError, ValueError):
                    v = self.exec(code) - 1073741824
            else:
                v = (self.metadata_frame(token, offset) if native else self.exec(code)) - 1073741824
            if not 0 <= v < 2**24:
                raise ValueError('Invalid export frame')
            return v.to_bytes(3, 'little')

        with ThreadPoolExecutor(max_workers=FRAME_WORKERS) as pool:
            data = b''.join(pool.map(word, range(0, size, 3)))[:size]
        result = read_export(data) if compressed else json.loads(data)
        if not isinstance(result, dict):
            raise ValueError('Guest metadata object required')
        return result

    def prepare_frames(self, path, token):
        """Have the guest write one tiny batch file per frame. Starting cmd.exe is far cheaper than PowerShell.

        The channel stays one-way: the host only reads exit codes, and the host shares stay read-only.
        """
        uuid.UUID(hex=token)
        folder = 'C:/SentinelAV-Test/Qualification/' + token + '/frames'
        code = (
            "$ErrorActionPreference='Stop';$b=[IO.File]::ReadAllBytes("
            + quote(path)
            + ");$d="
            + quote(folder)
            + ";New-Item $d -ItemType Directory -Force|Out-Null;"
            "for($o=0;$o -lt $b.Length;$o+=3){$v=0;for($i=0;$i -lt 3;$i++){if(($o+$i) -lt $b.Length){$v=$v -bor ([int]$b[$o+$i] -shl (8*$i))}};"
            "[IO.File]::WriteAllText(\"$d/$o.cmd\",\"@exit /b $(1073741824+$v)\")};exit 0"
        )
        try:
            return self.exec(code, 600) == 0
        except (RuntimeError, OSError, InterruptedError):
            return False

    def batch_frame(self, token, offset):
        """Read one prepared frame by running its tiny batch file and returning the exit code."""
        uuid.UUID(hex=token)
        if type(offset) is not int or offset < 0:
            raise ValueError('Invalid evidence offset')
        command = (
            'cmd.exe /d /c C:\\SentinelAV-Test\\Qualification\\'
            + token
            + '\\frames\\'
            + str(offset)
            + '.cmd'
        )
        reply = json.loads(
            run(
                [
                    'wsb.exe',
                    'exec',
                    '--id',
                    self.owner['guest_id'],
                    '-r',
                    'ExistingLogin',
                    '-c',
                    command,
                    '--raw',
                ],
                30,
                self.cancelled,
            )
        )
        value = reply.get('ExitCode')
        if type(value) is not int:
            raise ValueError('Batch evidence exit code missing')
        return value

    def metadata_frame(self, token, offset):
        """Read one frame through the native collector's export mode (offset -1 returns the file size)."""
        if token != 'setup':
            uuid.UUID(hex=token)
        if type(offset) is not int or not -1 <= offset < 32768:
            raise ValueError('Invalid native evidence offset')
        command = subprocess.list2cmdline(
            [
                'C:/Program Files/SentinelAV-Lab-Collector/SentinelAV.Telemetry.exe',
                '--lab-export',
                token,
                str(offset),
            ]
        )
        reply = json.loads(
            run(
                [
                    'wsb.exe',
                    'exec',
                    '--id',
                    self.owner['guest_id'],
                    '-r',
                    'ExistingLogin',
                    '-c',
                    command,
                    '--raw',
                ],
                30,
                self.cancelled,
            )
        )
        value = reply.get('ExitCode')
        if type(value) is not int:
            raise ValueError('Native evidence exit code missing')
        return value
