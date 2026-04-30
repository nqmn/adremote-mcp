param(
    [string]$VenvDir = ".venv-win"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing SSH MCP Server for Windows..."

if ($env:PYTHON) {
    $pythonExe = $env:PYTHON
    $pythonArgs = @()
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
    $pythonArgs = @()
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
    $pythonArgs = @("-3")
} else {
    throw "No Windows Python was found. Install Python 3.10+ or set the PYTHON environment variable."
}

Write-Host "Creating virtual environment: $VenvDir"
& $pythonExe @pythonArgs -m venv $VenvDir

$venvPython = Join-Path $VenvDir "Scripts\python.exe"

Write-Host "Installing dependencies..."
& $venvPython -m pip install -r requirements.txt

Write-Host ""
Write-Host "Installation complete."
Write-Host "MCP command:"
Write-Host (Resolve-Path $venvPython)
Write-Host "MCP args:"
Write-Host (Resolve-Path ".\ssh_mcp_server.py")
