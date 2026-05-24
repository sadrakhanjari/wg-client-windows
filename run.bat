@echo off
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c','cd /d \"%~dp0\" && python main.py' -Verb RunAs"
    exit /b
)
python main.py
