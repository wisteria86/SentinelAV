@echo off
rem Purpose: Live demo. Opens SentinelAV inside an offline Windows Sandbox and scans a theZoo sample there.
rem Works with: demo\guest-demo.ps1
rem On this PC the sample exists only encrypted (demo\fetch_sample.py), so it is never readable or run here.
rem The Sandbox decrypts it back to theZoo's password-protected ZIP, which SentinelAV reads in memory.
rem The Sandbox has no network and is wiped when closed.
setlocal

rem Files next to this script come first, so a copied folder works on another PC:
rem   demo\samples         encrypted samples (in the repository)
rem   demo-kit\SentinelAV  the packaged app (copy of F:\SentinelAV-Work\builds\dist\SentinelAV)
rem   demo-kit\definitions the definitions (copy of F:\SentinelAV-Work\snapshots\eval-freeze-90)
set "APP=F:\SentinelAV-Work\builds\dist\SentinelAV"
set "DEFS=F:\SentinelAV-Work\snapshots\eval-freeze-90"
set "SAMPLES=F:\SentinelAV-Work\demo\samples"
if exist "%~dp0demo-kit\SentinelAV\SentinelAV.exe" set "APP=%~dp0demo-kit\SentinelAV"
if exist "%~dp0demo-kit\definitions\snapshot.json" set "DEFS=%~dp0demo-kit\definitions"
if exist "%~dp0demo\samples\*.sealed" set "SAMPLES=%~dp0demo\samples"
set "DEMO=%~dp0demo"
set "WSB=%TEMP%\SampleRun.wsb"

echo.
echo   SentinelAV live demo
echo   ====================
echo.

if not exist "%WINDIR%\System32\WindowsSandbox.exe" (
    echo   Windows Sandbox is not enabled on this PC.
    echo   Turn it on in "Turn Windows features on or off", restart, and run this again.
    goto :fail
)
for %%P in ("%APP%\SentinelAV.exe" "%DEFS%\snapshot.json" "%DEMO%\guest-demo.ps1") do (
    if not exist "%%~P" ( echo   Missing: %%~P & goto :fail )
)
if not exist "%SAMPLES%\*.sealed" ( echo   No sample in %SAMPLES%. Run: .venv\Scripts\python.exe demo\fetch_sample.py & goto :fail )
tasklist /fi "imagename eq WindowsSandboxRemoteSession.exe" 2>nul | find /i "WindowsSandbox" >nul && (
    echo   A Windows Sandbox is already open. Close it first; only one can run at a time.
    goto :fail
)
for /f %%F in ('powershell -NoProfile -Command "[int]((Get-PSDrive C).Free/1GB)"') do set FREE=%%F
if %FREE% LSS 6 echo   Warning: only %FREE% GB free on C:. The Sandbox may be slow to start or fail.

rem Everything from this PC is mapped read-only; networking and the shared clipboard are off.
(
echo ^<Configuration^>
echo   ^<Networking^>Disable^</Networking^>
echo   ^<ClipboardRedirection^>Disable^</ClipboardRedirection^>
echo   ^<PrinterRedirection^>Disable^</PrinterRedirection^>
echo   ^<AudioInput^>Disable^</AudioInput^>
echo   ^<VideoInput^>Disable^</VideoInput^>
echo   ^<MemoryInMB^>4096^</MemoryInMB^>
echo   ^<MappedFolders^>
echo     ^<MappedFolder^>^<HostFolder^>%APP%^</HostFolder^>^<SandboxFolder^>C:\SentinelAV^</SandboxFolder^>^<ReadOnly^>true^</ReadOnly^>^</MappedFolder^>
echo     ^<MappedFolder^>^<HostFolder^>%DEFS%^</HostFolder^>^<SandboxFolder^>C:\Definitions^</SandboxFolder^>^<ReadOnly^>true^</ReadOnly^>^</MappedFolder^>
echo     ^<MappedFolder^>^<HostFolder^>%SAMPLES%^</HostFolder^>^<SandboxFolder^>C:\Samples^</SandboxFolder^>^<ReadOnly^>true^</ReadOnly^>^</MappedFolder^>
echo     ^<MappedFolder^>^<HostFolder^>%DEMO%^</HostFolder^>^<SandboxFolder^>C:\Demo^</SandboxFolder^>^<ReadOnly^>true^</ReadOnly^>^</MappedFolder^>
echo   ^</MappedFolders^>
echo   ^<LogonCommand^>^<Command^>powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -File C:\Demo\guest-demo.ps1^</Command^>^</LogonCommand^>
echo ^</Configuration^>
) > "%WSB%"

echo   Starting the Sandbox (offline, read-only access to this PC)...
echo   SentinelAV opens there by itself and scans the sample in about a minute.
echo   Close the Sandbox window when you are done; everything inside it is erased.
start "" "%WSB%"
exit /b 0

:fail
echo.
pause
exit /b 1
