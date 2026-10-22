# Aegis PowerShell Task Runner for Windows
param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

$Python = "python"
if (Test-Path ".\.venv\Scripts\python.exe") {
    $Python = ".\.venv\Scripts\python.exe"
}

switch ($Command.ToLower()) {
    "install" {
        & $Python -m pip install -e packages/aegis-guard -e apps/aegishome
    }
    "test-unit" {
        & $Python -m pytest -v
    }
    "evals" {
        & $Python apps/aegishome/evals/run_evals.py
    }
    "test" {
        Write-Host "Running unit tests..." -ForegroundColor Cyan
        & $Python -m pytest -v
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Write-Host "Running safety evals..." -ForegroundColor Cyan
        & $Python apps/aegishome/evals/run_evals.py
    }
    "demo" {
        Write-Host "Starting AegisHome MCP Web Server on http://127.0.0.1:8000/ ..." -ForegroundColor Green
        & $Python -m aegishome.main --host 127.0.0.1 --port 8000
    }
    default {
        Write-Host "Aegis Task Runner" -ForegroundColor Yellow
        Write-Host "Usage: .\run.ps1 [command]"
        Write-Host "Commands:"
        Write-Host "  test       Run unit tests + safety evals"
        Write-Host "  demo       Launch web dashboard on port 8000"
        Write-Host "  evals      Run 61 red-teaming evals"
        Write-Host "  test-unit  Run pytest suite"
        Write-Host "  install    Install packages in editable mode"
    }
}
