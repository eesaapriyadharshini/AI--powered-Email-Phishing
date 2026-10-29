@echo off
setlocal
cd /d "%~dp0"
python --version >nul 2>&1
if not errorlevel 1 (
  python backend\server.py
  goto :finished
)
py -3.13 --version >nul 2>&1
if not errorlevel 1 (
  py -3.13 backend\server.py
  goto :finished
)
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" backend\server.py
  goto :finished
)
echo Python 3.10+ was not found. Install Python from python.org, then run this file again.
pause
exit /b 1
:finished
if errorlevel 1 (
  echo.
  echo PhishGuard stopped with an error. Make sure port 8000 is available and Python 3.10+ is installed.
  pause
)
