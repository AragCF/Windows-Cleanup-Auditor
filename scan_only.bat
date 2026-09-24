@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "PY_CMD="
where py >nul 2>nul
if not errorlevel 1 set "PY_CMD=py -3"
if not defined PY_CMD (
  where python >nul 2>nul
  if not errorlevel 1 set "PY_CMD=python"
)

if not defined PY_CMD (
  echo ERROR: Python 3 was not found.
  pause
  exit /b 2
)

if not exist "logs" mkdir "logs"
if not exist "reports" mkdir "reports"

set "ROOT_ARG=%~1"
if not defined ROOT_ARG set "ROOT_ARG=%SystemDrive%"
if "!ROOT_ARG:~-1!"=="\" set "ROOT_ARG=!ROOT_ARG:~0,-1!"

if /I "!ROOT_ARG!"=="ALL" (
  echo Scan mode: all fixed drives
  %PY_CMD% "%~dp0windows_cleanup_auditor.py" --cli --all-drives
) else (
  echo Scan root: !ROOT_ARG!\
  %PY_CMD% "%~dp0windows_cleanup_auditor.py" --cli --root "!ROOT_ARG!"
)

set "RC=%ERRORLEVEL%"
echo.
echo Exit code: %RC%
echo Reports: "%~dp0reports"
pause
exit /b %RC%
