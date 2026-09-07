$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

# Online mode requires DF_API_KEY to be set by the user before running this script.
# Example:
#   $env:DF_API_KEY = "your_deepseek_api_key"
# If your network needs a proxy, set HTTP_PROXY/HTTPS_PROXY/ALL_PROXY yourself before running.
$env:DF_LOGGING_LEVEL = "INFO"

$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Write-Host "DataFlow 9-case experiments" -ForegroundColor Cyan
Write-Host "Working directory: $ProjectRoot"
Write-Host "Python: $PythonExe"
Write-Host "Displayed times: Dec 2025 to early Feb 2026 evening records"
Write-Host "Online mode: DF_API_KEY must be set in the current user/session environment."
Write-Host ""

if (-not $env:DF_API_KEY) {
    Write-Host "ERROR: DF_API_KEY is not set. Please set it before running this script." -ForegroundColor Red
    Write-Host 'Example: $env:DF_API_KEY = "your_deepseek_api_key"' -ForegroundColor Yellow
    exit 1
}

& $PythonExe (Join-Path $ProjectRoot "scripts\run_dataflow_cases.py")

Write-Host ""
Write-Host "All done. Press Enter to keep/close this window manually." -ForegroundColor Green
[void][System.Console]::ReadLine()
