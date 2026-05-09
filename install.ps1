param(
    [string]$InstallDir = "$env:USERPROFILE\adremote-mcp"
)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/nqmn/adremote-mcp"
$VenvDir = ".venv-win"

# If already inside the repo, install in place
if (Test-Path ".\ssh_mcp_server.py") {
    $InstallDir = (Get-Location).Path
    Write-Host "Found ssh_mcp_server.py — installing in current directory."
} else {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "git is required. Install Git for Windows and try again."
        exit 1
    }
    Write-Host "Cloning adremote-mcp into $InstallDir ..."
    git clone $RepoUrl $InstallDir
    Set-Location $InstallDir
}

# Find Python
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
    Write-Error "No Python found. Install Python 3.10+ or set the PYTHON environment variable."
    exit 1
}

$venvPath = Join-Path $InstallDir $VenvDir
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$serverPath = Join-Path $InstallDir "ssh_mcp_server.py"

Write-Host "Creating virtual environment: $venvPath"
& $pythonExe @pythonArgs -m venv $venvPath

Write-Host "Installing dependencies..."
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet -r (Join-Path $InstallDir "requirements.txt")

Write-Host ""
Write-Host "Installation complete."
Write-Host ""
Write-Host "Add this to your MCP client config:"
Write-Host "  {"
Write-Host "    `"mcpServers`": {"
Write-Host "      `"ssh-remote`": {"
Write-Host "        `"command`": `"$venvPython`","
Write-Host "        `"args`": [`"$serverPath`"]"
Write-Host "      }"
Write-Host "    }"
Write-Host "  }"
