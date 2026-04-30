@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "VENV_PY=%SCRIPT_DIR%.venv-win\Scripts\python.exe"

if exist "%VENV_PY%" (
  "%VENV_PY%" "%SCRIPT_DIR%ssh_mcp_server.py"
  exit /b %ERRORLEVEL%
)

if not "%SSH_MCP_PYTHON%"=="" (
  "%SSH_MCP_PYTHON%" "%SCRIPT_DIR%ssh_mcp_server.py"
  exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%SCRIPT_DIR%ssh_mcp_server.py"
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%SCRIPT_DIR%ssh_mcp_server.py"
  exit /b %ERRORLEVEL%
)

echo No Windows Python was found. Run install.ps1 or install Python 3.10+.
exit /b 1
