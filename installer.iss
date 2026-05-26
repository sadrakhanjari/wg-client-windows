; Inno Setup script — wraps the PyInstaller build into a Windows setup wizard.
; 1) Run build.bat first (produces dist\LocalWireGuard\).
; 2) Install Inno Setup (https://jrsoftware.org/isdl.php), then compile this
;    file with the Inno Setup Compiler (ISCC.exe) to get LocalWireGuard-Setup.exe.

#define MyAppName "Local WireGuard"
#define MyAppVersion "1.0"
#define MyAppExe "LocalWireGuard.exe"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=sadrakhanjari
DefaultDirName={autopf}\LocalWireGuard
DefaultGroupName=Local WireGuard
DisableProgramGroupPage=yes
OutputBaseFilename=LocalWireGuard-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The app needs admin (Wintun adapter creation), so install per-machine.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=app.ico

[Files]
Source: "dist\LocalWireGuard\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
