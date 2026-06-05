; AegisEDR Agent — Inno Setup 6 Installer Script
; Build: ISCC.exe AegisEDR_Agent.iss

#define AppName      "AegisEDR Agent"
#define AppVersion   "1.0.0"
#define AppPublisher "AegisEDR Security"
#define AppURL       "https://aegisedr.local"
#define AppExeName   "AegisEDR-Agent.exe"
#define ServiceName  "AegisEDRAgent"

[Setup]
AppId={{B4E7A1C2-8F3D-4A9E-B2C1-7D5F8E9A0B3C}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} v{#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\AegisEDR
DefaultGroupName={#AppName}
AllowNoIcons=no
LicenseFile=..\assets\LICENSE.rtf
OutputDir=..\dist
OutputBaseFilename=AegisEDR-Agent-Setup-v{#AppVersion}
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile=..\assets\logo_wizard.bmp
WizardSmallImageFile=..\assets\logo_header.bmp
WizardImageStretch=no
WizardSizePercent=120
PrivilegesRequired=admin
MinVersion=10.0
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
CreateUninstallRegKey=yes
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Create a &desktop icon";     GroupDescription: "Additional icons:"; Flags: unchecked
Name: "starttray";     Description: "Start &tray monitor on login"; GroupDescription: "Startup:"
Name: "runonstartup";  Description: "Run agent as &Windows service (recommended)"; GroupDescription: "Service:"; Flags: checkablealone

[Files]
; Main agent executable (built with PyInstaller)
Source: "..\dist\AegisEDR-Agent.exe";    DestDir: "{app}"; Flags: ignoreversion
; Tray monitor
Source: "..\dist\AegisEDR-Tray.exe";    DestDir: "{app}"; Flags: ignoreversion; Check: FileExists('..\dist\AegisEDR-Tray.exe')
; YARA rules
Source: "..\yara_rules\*";              DestDir: "{app}\yara_rules"; Flags: ignoreversion recursesubdirs
; Assets
Source: "..\assets\icon.ico";           DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\logo.png";           DestDir: "{app}"; Flags: ignoreversion; Check: FileExists('..\assets\logo.png')

[Icons]
Name: "{group}\{#AppName}";             Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\AegisEDR Tray Monitor";  Filename: "{app}\AegisEDR-Tray.exe"; IconFilename: "{app}\icon.ico"; Check: FileExists(ExpandConstant('{app}\AegisEDR-Tray.exe'))
Name: "{group}\View Logs";              Filename: "{app}\logs\agent.log"; Flags: dontcloseonexit
Name: "{group}\Uninstall {#AppName}";   Filename: "{uninstallexe}"
Name: "{userdesktop}\{#AppName}";       Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon
Name: "{userstartup}\AegisEDR Tray";    Filename: "{app}\AegisEDR-Tray.exe"; Tasks: starttray; Check: FileExists(ExpandConstant('{app}\AegisEDR-Tray.exe'))

[Dirs]
Name: "{app}\logs"
Name: "{app}\quarantine"
Name: "{app}\data"

[Code]
var
  ConsoleUrlPage: TInputQueryWizardPage;
  ConsoleUrl: String;
  StatusLabel: TLabel;

{ ── Custom wizard page: Console URL ── }
procedure InitializeWizard;
begin
  ConsoleUrlPage := CreateInputQueryPage(wpLicense,
    'AegisEDR Console Connection',
    'Connect this endpoint to your AegisEDR Security Console',
    'Enter the URL of your AegisEDR Console appliance.' + #13#10 +
    'Example: https://192.168.1.100  or  http://192.168.1.100:9000');

  ConsoleUrlPage.Add('Console URL:', False);
  ConsoleUrlPage.Values[0] := 'http://';
  ConsoleUrlPage.Edits[0].Width := ScaleX(340);
end;

{ ── Validate console URL ── }
function NextButtonClick(CurPageID: Integer): Boolean;
var
  url: String;
begin
  Result := True;
  if CurPageID = ConsoleUrlPage.ID then begin
    url := Trim(ConsoleUrlPage.Values[0]);
    if (url = '') or (url = 'http://') or (url = 'https://') then begin
      MsgBox('Please enter a valid Console URL.' + #13#10 +
             'Example: http://192.168.1.100:9000', mbError, MB_OK);
      Result := False;
    end else begin
      ConsoleUrl := url;
    end;
  end;
end;

{ ── Post-install actions ── }
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  ConfigPath, LogDir: String;
begin
  if CurStep = ssPostInstall then begin

    { Save config }
    ConfigPath := ExpandConstant('{commonappdata}\AegisEDR\config.json');
    ForceDirectories(ExtractFilePath(ConfigPath));
    SaveStringToFile(ConfigPath,
      '{' + #13#10 +
      '  "console_url": "' + ConsoleUrl + '",' + #13#10 +
      '  "agent_version": "' + '{#AppVersion}' + '"' + #13#10 +
      '}', False);

    { Install as scheduled task (service-like) if chosen }
    if IsTaskSelected('runonstartup') then begin
      Exec('schtasks.exe',
        '/Create /F /TN "' + '{#ServiceName}' + '" ' +
        '/TR "\"' + ExpandConstant('{app}\{#AppExeName}') + '\" ' + ConsoleUrl + '" ' +
        '/SC ONSTART /RU SYSTEM /RL HIGHEST /DELAY 0000:30',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

      { Start immediately }
      Exec('schtasks.exe', '/Run /TN "' + '{#ServiceName}' + '"',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    { Start tray monitor }
    if IsTaskSelected('starttray') then begin
      if FileExists(ExpandConstant('{app}\AegisEDR-Tray.exe')) then
        Exec(ExpandConstant('{app}\AegisEDR-Tray.exe'), '', '', SW_SHOW, ewNoWait, ResultCode);
    end;

  end;
end;

{ ── Uninstall: remove scheduled task ── }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then begin
    Exec('schtasks.exe', '/Delete /TN "' + '{#ServiceName}' + '" /F',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

{ ── Success message ── }
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine +
            'Console URL:' + NewLine +
            Space + ConsoleUrl + NewLine + NewLine +
            MemoTasksInfo;
end;
