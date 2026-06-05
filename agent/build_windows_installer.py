"""
Build script for AegisEDR Windows Agent installer.
Prerequisites:
  pip install pyinstaller
  Install Inno Setup 6 from https://jrsoftware.org/isdl.php

Usage:
  python build_windows_installer.py [console_url]
  python build_windows_installer.py http://192.168.1.100:9000
"""
import os
import sys
import subprocess
import shutil
import textwrap

AGENT_VERSION = "1.0.0"
BUILD_DIR = os.path.join(os.path.dirname(__file__), "..", "dist")
AGENT_SRC = os.path.join(os.path.dirname(__file__), "agent_windows.py")
INNO_SETUP = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

# Default console URL (can be overridden at install time via wizard)
DEFAULT_CONSOLE = sys.argv[1] if len(sys.argv) > 1 else "http://CONSOLE_IP:9000"

def step(msg):
    print(f"\n{'='*50}")
    print(f"  {msg}")
    print('='*50)

def build_exe():
    step("Step 1: Building standalone .exe with PyInstaller")
    os.makedirs(BUILD_DIR, exist_ok=True)

    cmd = [
        "pyinstaller",
        "--onefile",
        "--name", "AegisEDR-Agent",
        "--icon", os.path.join(os.path.dirname(__file__), "icon.ico") if os.path.exists(
            os.path.join(os.path.dirname(__file__), "icon.ico")) else "NONE",
        "--hidden-import", "watchdog.observers.winapi",
        "--hidden-import", "win32security",
        "--hidden-import", "win32api",
        "--add-data", f"{os.path.dirname(__file__)};.",
        "--distpath", BUILD_DIR,
        "--workpath", os.path.join(BUILD_DIR, "build_tmp"),
        "--specpath", BUILD_DIR,
        "--noconfirm",
        AGENT_SRC
    ]
    # Remove icon flag if no icon
    cmd = [c for c in cmd if c != "NONE" and not (c == "--icon" and "NONE" in cmd)]

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("ERROR: PyInstaller failed")
        sys.exit(1)
    print(f"✓ EXE built: {BUILD_DIR}\\AegisEDR-Agent.exe")

def build_inno_installer():
    step("Step 2: Building Windows installer with Inno Setup")

    iss_content = textwrap.dedent(f"""
        #define AppName "AegisEDR Agent"
        #define AppVersion "{AGENT_VERSION}"
        #define AppPublisher "AegisEDR Security"
        #define AppExeName "AegisEDR-Agent.exe"

        [Setup]
        AppId={{{{B4E7A1C2-8F3D-4A9E-B2C1-7D5F8E9A0B3C}}}}
        AppName={{#AppName}}
        AppVersion={{#AppVersion}}
        AppPublisher={{#AppPublisher}}
        DefaultDirName={{commonpf64}}\\AegisEDR
        DefaultGroupName={{#AppName}}
        OutputDir={BUILD_DIR}
        OutputBaseFilename=AegisEDR-Agent-Setup-v{AGENT_VERSION}
        Compression=lzma2/ultra64
        SolidCompression=yes
        PrivilegesRequired=admin
        SetupIconFile=
        WizardStyle=modern
        WizardSmallImageFile=
        UninstallDisplayIcon={{app}}\\{{#AppExeName}}

        [Languages]
        Name: "english"; MessagesFile: "compiler:Default.isl"

        [CustomMessages]
        ConsoleUrlLabel=AegisEDR Console URL:
        ConsoleUrlDesc=Enter the IP/hostname of your AegisEDR Console server.

        [Code]
        var
          ConsoleUrlPage: TInputQueryWizardPage;
          ConsoleUrl: String;

        procedure InitializeWizard;
        begin
          ConsoleUrlPage := CreateInputQueryPage(wpWelcome,
            'AegisEDR Console',
            'Connect to AegisEDR Security Console',
            'Enter the URL of your AegisEDR Console. Example: http://192.168.1.100:9000');
          ConsoleUrlPage.Add('Console URL:', False);
          ConsoleUrlPage.Values[0] := '{DEFAULT_CONSOLE}';
        end;

        function NextButtonClick(CurPageID: Integer): Boolean;
        begin
          Result := True;
          if CurPageID = ConsoleUrlPage.ID then begin
            ConsoleUrl := ConsoleUrlPage.Values[0];
            if ConsoleUrl = '' then begin
              MsgBox('Please enter the Console URL.', mbError, MB_OK);
              Result := False;
            end;
          end;
        end;

        procedure CurStepChanged(CurStep: TSetupStep);
        var
          ResultCode: Integer;
        begin
          if CurStep = ssPostInstall then begin
            // Save console URL config
            SaveStringToFile(ExpandConstant('{{app}}\\console.url'), ConsoleUrl, False);
            // Register and start as service via Task Scheduler
            Exec('schtasks.exe',
              '/Create /TN "AegisEDRAgent" /TR "\"' + ExpandConstant('{{app}}\\{{#AppExeName}}') +
              '\" ' + ConsoleUrl + '" /SC ONSTART /RU SYSTEM /RL HIGHEST /F',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
            // Start immediately
            Exec('schtasks.exe', '/Run /TN "AegisEDRAgent"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
          end;
        end;

        [Files]
        Source: "{BUILD_DIR}\\AegisEDR-Agent.exe"; DestDir: "{{app}}"; Flags: ignoreversion

        [Icons]
        Name: "{{group}}\\AegisEDR Agent"; Filename: "{{app}}\\{{#AppExeName}}"
        Name: "{{group}}\\Uninstall AegisEDR Agent"; Filename: "{{uninstallexe}}"

        [Run]
        Filename: "{{app}}\\{{#AppExeName}}"; Description: "Launch AegisEDR Agent"; Flags: nowait postinstall skipifsilent

        [UninstallRun]
        Filename: "schtasks.exe"; Parameters: "/Delete /TN AegisEDRAgent /F"; Flags: runhidden

        [Tasks]
        Name: "startservice"; Description: "Start agent immediately after install"; GroupDescription: "Additional tasks:"
    """).strip()

    iss_path = os.path.join(BUILD_DIR, "aegisedr_agent.iss")
    with open(iss_path, "w") as f:
        f.write(iss_content)

    if not os.path.exists(INNO_SETUP):
        print(f"\n⚠  Inno Setup not found at: {INNO_SETUP}")
        print("   Install from: https://jrsoftware.org/isdl.php")
        print(f"   Then run: \"{INNO_SETUP}\" \"{iss_path}\"")
        print(f"\n✓  .ISS file saved to: {iss_path}")
        return

    result = subprocess.run([INNO_SETUP, iss_path])
    if result.returncode == 0:
        installer = os.path.join(BUILD_DIR, f"AegisEDR-Agent-Setup-v{AGENT_VERSION}.exe")
        print(f"\n✓ Installer built: {installer}")
    else:
        print("ERROR: Inno Setup compilation failed")
        sys.exit(1)

if __name__ == "__main__":
    print(f"AegisEDR Windows Agent Builder v{AGENT_VERSION}")
    print(f"Console URL: {DEFAULT_CONSOLE}")
    build_exe()
    build_inno_installer()
    print("\n✓ Done!")
