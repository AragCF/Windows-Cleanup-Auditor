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
  echo Install Python 3 and enable Add Python to PATH.
  pause
  exit /b 2
)

if not exist "logs" mkdir "logs"
set "LOG=logs\launcher.log"

>> "%LOG%" echo.
>> "%LOG%" echo [%date% %time%] Starting Windows Cleanup Auditor
>> "%LOG%" echo Working directory: %CD%

echo Starting Windows Cleanup Auditor...
%PY_CMD% "%~dp0windows_cleanup_auditor.py" >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"

>> "%LOG%" echo [%date% %time%] Exit code: %RC%

echo.
if not "%RC%"=="0" (
  echo ERROR: application exited with code %RC%.
  echo Log: "%~dp0%LOG%"
) else (
  echo Application finished.
  echo Log: "%~dp0%LOG%"
)
echo.
pause
exit /b %RC%
