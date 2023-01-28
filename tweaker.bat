@echo off 
if not "%1"=="am_admin" (powershell start -verb runas '%0' am_admin & exit /b)
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Start_ShowClassicMode /T REG_DWORD /D 1 /F
