@echo off
REM Build a standalone, admin-elevating LocalWireGuard.exe with PyInstaller.
REM Output: dist\LocalWireGuard\LocalWireGuard.exe
cd /d "%~dp0"

echo [1/2] Generating app icon from appicon.png...
python3.12 -c "from PIL import Image; Image.open('appicon.png').save('app.ico',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"

echo [2/2] Building with PyInstaller...
python3.12 -m PyInstaller --noconfirm --clean --windowed --uac-admin ^
  --name LocalWireGuard ^
  --icon app.ico ^
  --add-binary "vendor\wintun.dll;vendor" ^
  --add-data "appicon.png;." ^
  --collect-data customtkinter ^
  --collect-submodules pystray ^
  --collect-submodules PIL ^
  main.py

echo.
echo Done. Run: dist\LocalWireGuard\LocalWireGuard.exe
echo (It requests admin automatically via UAC.)
pause
