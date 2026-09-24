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

%PY_CMD% "%~dp0pack_reports_for_git.py"
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
