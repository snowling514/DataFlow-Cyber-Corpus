$ErrorActionPreference = "Stop"

Set-Location "C:\Users\Admin\Documents\DataFlow"

$env:HTTP_PROXY = "http://127.0.0.1:7890"
$env:HTTPS_PROXY = "http://127.0.0.1:7890"
$env:ALL_PROXY = "http://127.0.0.1:7890"
$env:DF_LOGGING_LEVEL = "INFO"

Write-Host "DataFlow 9-case experiments" -ForegroundColor Cyan
Write-Host "Working directory: C:\Users\Admin\Documents\DataFlow"
Write-Host "Virtual environment: .venv"
Write-Host "Displayed times: Dec 2025 to early Feb 2026 evening records"
Write-Host ""

& ".\.venv\Scripts\python.exe" ".\scripts\run_dataflow_cases.py"

Write-Host ""
Write-Host "All done. Press Enter to keep/close this window manually." -ForegroundColor Green
[void][System.Console]::ReadLine()

