# ==============================================================================
# make.ps1 - PowerShell Equivalent for Windows
# Usage: .\make.ps1 <target>
# Targets: install, test, evals, smoke, demo, check-secrets, all-checks, clean
# ==============================================================================

param (
    [Parameter(Position = 0)]
    [string]$Target = "help"
)

# Prefer current virtualenv python if present, else fallback to PATH python
$VENV_PYTHON = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $VENV_PYTHON) {
    $PYTHON = $VENV_PYTHON
} else {
    $PYTHON = "python"
}

switch ($Target.ToLower()) {
    "help" {
        Write-Host "Aegis - Alexa+ MCP Safety Gateway (PowerShell Runner)" -ForegroundColor Cyan
        Write-Host "----------------------------------------------------"
        Write-Host ".\make.ps1 install        Install both packages in editable mode"
        Write-Host ".\make.ps1 test           Run full pytest suite and safety evaluations"
        Write-Host ".\make.ps1 evals          Run adversarial evaluation benchmark (61 red-teaming cases)"
        Write-Host ".\make.ps1 smoke          Run end-to-end integration smoke test"
        Write-Host ".\make.ps1 demo           Launch interactive web dashboard & MCP server (port 8000)"
        Write-Host ".\make.ps1 check-secrets  Scan repo for leaked API keys, tokens, or private keys"
        Write-Host ".\make.ps1 all-checks     Run check-secrets, test, and smoke test with summary"
        Write-Host ".\make.ps1 clean          Remove caches and temporary artifacts"
    }

    "install" {
        Write-Host "Installing packages with dev dependencies in editable mode..." -ForegroundColor Cyan
        & $PYTHON -m pip install -e "packages/aegis-guard[dev]" -e "apps/aegishome[dev]"
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    "test" {
        Write-Host "Running pytest suite..." -ForegroundColor Cyan
        & $PYTHON -m pytest -v
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host "`nRunning adversarial safety evals..." -ForegroundColor Cyan
        & $PYTHON apps/aegishome/evals/run_evals.py
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    "evals" {
        Write-Host "Running adversarial safety evals (61 red-teaming cases)..." -ForegroundColor Cyan
        & $PYTHON apps/aegishome/evals/run_evals.py
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    "smoke" {
        Write-Host "Running smoke test..." -ForegroundColor Cyan
        & $PYTHON scripts/smoke_test.py
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    "demo" {
        Write-Host "Launching Aegis Caregiver Dashboard on http://127.0.0.1:8000 ..." -ForegroundColor Green
        & $PYTHON -m aegishome.main --host 127.0.0.1 --port 8000
    }

    "check-secrets" {
        Write-Host "Scanning repository for leaked credentials..." -ForegroundColor Cyan
        & $PYTHON scripts/check_secrets.py
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    "all-checks" {
        Write-Host "`n==========================================================" -ForegroundColor Cyan
        Write-Host "Running All Quality, Security & Safety Verification Checks" -ForegroundColor Cyan
        Write-Host "==========================================================" -ForegroundColor Cyan

        $summary = @{}

        Write-Host "`n[Step 1/4] Scanning repository for secrets..." -ForegroundColor Yellow
        & $PYTHON scripts/check_secrets.py
        if ($LASTEXITCODE -eq 0) { $summary["check-secrets"] = "PASS" } else { $summary["check-secrets"] = "FAIL" }

        Write-Host "`n[Step 2/4] Running pytest unit/integration suite..." -ForegroundColor Yellow
        & $PYTHON -m pytest -v
        if ($LASTEXITCODE -eq 0) { $summary["pytest"] = "PASS" } else { $summary["pytest"] = "FAIL" }

        Write-Host "`n[Step 3/4] Running adversarial safety evals..." -ForegroundColor Yellow
        & $PYTHON apps/aegishome/evals/run_evals.py
        if ($LASTEXITCODE -eq 0) { $summary["evals"] = "PASS" } else { $summary["evals"] = "FAIL" }

        Write-Host "`n[Step 4/4] Running end-to-end integration smoke test..." -ForegroundColor Yellow
        & $PYTHON scripts/smoke_test.py
        if ($LASTEXITCODE -eq 0) { $summary["smoke"] = "PASS" } else { $summary["smoke"] = "FAIL" }

        Write-Host "`n================ SUMMARY ================" -ForegroundColor Cyan
        $anyFailed = $false
        foreach ($key in $summary.Keys) {
            $status = $summary[$key]
            if ($status -eq "PASS") {
                Write-Host "  $key : PASS" -ForegroundColor Green
            } else {
                Write-Host "  $key : FAIL" -ForegroundColor Red
                $anyFailed = $true
            }
        }
        Write-Host "=========================================" -ForegroundColor Cyan

        if ($anyFailed) {
            Write-Host "[-] Some verification checks failed." -ForegroundColor Red
            exit 1
        } else {
            Write-Host "[+] ALL CHECKS PASSED: Ready for submission!" -ForegroundColor Green
            exit 0
        }
    }

    "clean" {
        Write-Host "Cleaning cache directories..." -ForegroundColor Cyan
        Get-ChildItem -Path . -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path . -Recurse -Directory -Filter ".pytest_cache" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Caches cleaned." -ForegroundColor Green
    }

    default {
        Write-Error "Unknown target '$Target'. Run '.\make.ps1 help' for available targets."
        exit 1
    }
}
