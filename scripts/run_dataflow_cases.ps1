$ErrorActionPreference = "Stop"

Set-Location "C:\Users\Admin\Documents\DataFlow"

# Online mode requires DF_API_KEY to be set by the user before running this script.
# Example:
#   $env:DF_API_KEY = "your_deepseek_api_key"
# If your network needs a proxy, set HTTP_PROXY/HTTPS_PROXY/ALL_PROXY yourself before running.
$env:DF_LOGGING_LEVEL = "INFO"

Write-Host "DataFlow 9-case experiments" -ForegroundColor Cyan
Write-Host "Working directory: C:\Users\Admin\Documents\DataFlow"
Write-Host "Virtual environment: .venv"
Write-Host "Displayed times: Dec 2025 to early Feb 2026 evening records"
Write-Host "Online mode: DF_API_KEY must be set in the current user/session environment."
Write-Host ""

if (-not $env:DF_API_KEY) {
    Write-Host "ERROR: DF_API_KEY is not set. Please set it before running this script." -ForegroundColor Red
    Write-Host 'Example: $env:DF_API_KEY = "your_deepseek_api_key"' -ForegroundColor Yellow
    exit 1
}

& ".\.venv\Scripts\python.exe" ".\scripts\run_dataflow_cases.py"

Write-Host ""
Write-Host "All done. Press Enter to keep/close this window manually." -ForegroundColor Green
[void][System.Console]::ReadLine()

