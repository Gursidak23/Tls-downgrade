@echo off
REM  Run all tests -- double-click or: run_all.bat
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0run_all.ps1"
pause
