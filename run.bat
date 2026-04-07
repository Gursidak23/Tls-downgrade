@echo off
REM ============================================================
REM  TLS Downgrade & Cipher Suite Analyzer -- Windows Launcher
REM  Double-click to run, or: run.bat [command]
REM  Commands: lab, stacks, server, profiles, demo, dashboard, all, install, help
REM ============================================================

cd /d "%~dp0"

if "%~1"=="" (
    powershell -ExecutionPolicy Bypass -File "%~dp0run.ps1" lab
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
)

pause
