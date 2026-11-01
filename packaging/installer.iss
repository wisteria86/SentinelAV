#define AppVersion "0.12.0"
[Setup]
SourceDir=..
AppId={{D9DEEB9C-64A4-48A2-BD0E-8B19B22908C5}
AppName=SentinelAV
AppVersion={#AppVersion}
AppPublisher=SentinelAV Student Project
DefaultDirName={localappdata}\Programs\SentinelAV
DefaultGroupName=SentinelAV
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=artifacts\release
OutputBaseFilename=SentinelAV-Setup-{#AppVersion}
SetupIconFile=resources\assets\sentinelav.ico
UninstallDisplayIcon={app}\SentinelAV.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes
InfoBeforeFile=docs\RELEASE-NOTES.txt
[Tasks]
Name: desktopicon; Description: "Create a Desktop shortcut"; Flags: unchecked
[Files]
Source: "artifacts\dist\SentinelAV\*"; DestDir: "{app}"; Excludes: "\_internal\signature-data\active.json,\_internal\trusted-update-keys.json"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "artifacts\dist\SentinelAV\_internal\trusted-update-keys.json"; DestDir: "{app}\_internal"; Flags: onlyifdoesntexist
#if FileExists("artifacts\dist\SentinelAV\_internal\signature-data\active.json")
Source: "artifacts\dist\SentinelAV\_internal\signature-data\active.json"; DestDir: "{app}\_internal\signature-data"; Flags: onlyifdoesntexist
#endif
[Icons]
Name: "{userprograms}\SentinelAV"; Filename: "{app}\SentinelAV.exe"
Name: "{userdesktop}\SentinelAV"; Filename: "{app}\SentinelAV.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\SentinelAV.exe"; Description: "Launch SentinelAV"; Flags: nowait postinstall skipifsilent
[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Service, Folder, Task: Variant;
    StartupCommand, AppExe: String;
begin
  if CurUninstallStep = usUninstall then begin
    AppExe := ExpandConstant('{app}\SentinelAV.exe');
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'SentinelAV', StartupCommand) then
      if (Pos('"' + AppExe + '"', StartupCommand) = 1) or (Pos(AppExe + ' ', StartupCommand) = 1) then
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'SentinelAV');
    try
      Service := CreateOleObject('Schedule.Service');
      Service.Connect();
      Folder := Service.GetFolder('\');
      Task := Folder.GetTask('SentinelAV Daily Scan');
      if CompareText(Task.Definition.Actions.Item(1).Path, AppExe) = 0 then
        Folder.DeleteTask('SentinelAV Daily Scan', 0);
    except
    end;
  end;
end;
