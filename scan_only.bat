@echo off
setlocal EnableExtensions
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

%PY_CMD% "%~dp0windows_cleanup_auditor.py" --cli
set "RC=%ERRORLEVEL%"
echo.
echo Exit code: %RC%
echo Reports: "%~dp0reports"
pause
exit /b %RC%
