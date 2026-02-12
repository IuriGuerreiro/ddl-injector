@echo off
REM Launch DLL Injector UI with UAC elevation
echo Starting DLL Injector...
start "" "%~dp0target\release\injector.exe"
echo UAC prompt should appear!
