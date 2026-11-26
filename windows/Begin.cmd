@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%ProgramFiles%\VpnGuard\Control.ps1" -Action Begin
if errorlevel 1 pause
