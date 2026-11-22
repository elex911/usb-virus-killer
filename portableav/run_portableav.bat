@echo off
rem ============================================================
rem  PortableAV launcher (WinPE / normal Windows)
rem
rem  Why this file exists:
rem  - PyInstaller onefile unpacks itself BEFORE Python starts,
rem    so setting TEMP inside Python code is too late.
rem  - This launcher sets TEMP/TMP before starting the runtime.
rem
rem  Usage:
rem    run_portableav.bat scan --target D:\Windows
rem    run_portableav.bat env
rem
rem  Optional:
rem    set PAV_WORK=D:\PortableAV_Work   (put temp/out on a writable disk)
rem  Default work dir is <this folder>\_work (i.e. the USB stick).
rem ============================================================
setlocal enableextensions
chcp 65001 >nul 2>&1

set "BASE=%~dp0"
set "WORK=%BASE%_work"
if defined PAV_WORK set "WORK=%PAV_WORK%"

if not exist "%WORK%\tmp" mkdir "%WORK%\tmp" >nul 2>&1
if not exist "%WORK%\tmp" (
    echo [ERROR] Cannot create work dir: %WORK%\tmp
    echo         Set PAV_WORK to a writable folder on a real disk.
    exit /b 2
)

rem TMPDIR matters: Python's tempfile checks TMPDIR -> TEMP -> TMP on Windows,
rem so setting only TEMP/TMP can be silently overridden by an inherited TMPDIR.
set "TMPDIR=%WORK%\tmp"
set "TEMP=%WORK%\tmp"
set "TMP=%WORK%\tmp"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONPATH=%BASE%"
set "PYTHONIOENCODING=utf-8"

echo [i] work dir : %WORK%
echo [i] TEMP     : %TEMP%

if exist "%BASE%runtime\python.exe" (
    "%BASE%runtime\python.exe" -m portableav %*
) else (
    rem fall back to system python (development machine)
    python -m portableav %*
)
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
