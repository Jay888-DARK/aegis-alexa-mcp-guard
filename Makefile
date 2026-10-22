.PHONY: all help install test test-unit evals smoke demo check-secrets all-checks clean

# Environment detection
PYTHON ?= $(shell which python3 2>/dev/null || which python 2>/dev/null || echo python)
PYTEST ?= $(PYTHON) -m pytest

help:
	@echo "Aegis - Alexa+ MCP Safety Gateway"
	@echo "-----------------------------------"
	@echo "make install        Install both packages in editable mode"
	@echo "make test           Run full pytest unit/integration suite and safety evaluations"
	@echo "make evals          Run adversarial evaluation benchmark (61 red-teaming cases)"
	@echo "make smoke          Run end-to-end integration smoke test"
	@echo "make demo           Launch interactive web dashboard & MCP server (port 8000)"
	@echo "make check-secrets  Scan repo for leaked API keys, tokens, or private keys"
	@echo "make all-checks     Run check-secrets, test, and smoke test with summary"
	@echo "make clean          Remove caches and temporary artifacts"

install:
	$(PYTHON) -m pip install -e "packages/aegis-guard[dev]" -e "apps/aegishome[dev]"

test-unit:
	$(PYTEST) -v

evals:
	$(PYTHON) apps/aegishome/evals/run_evals.py

test: test-unit evals

smoke:
	$(PYTHON) scripts/smoke_test.py

demo:
	$(PYTHON) -m aegishome.main --host 127.0.0.1 --port 8000

check-secrets:
	$(PYTHON) scripts/check_secrets.py

all-checks:
	@echo "=========================================================="
	@echo "Running All Quality, Security & Safety Verification Checks"
	@echo "=========================================================="
	@echo "\n[Step 1/3] Scanning repository for secrets..."
	@$(PYTHON) scripts/check_secrets.py
	@echo "\n[Step 2/3] Running pytest unit & integration test suite..."
	@$(PYTEST) -v
	@echo "\n[Step 3/3] Running adversarial safety evals & smoke test..."
	@$(PYTHON) apps/aegishome/evals/run_evals.py
	@$(PYTHON) scripts/smoke_test.py
	@echo "\n=========================================================="
	@echo "[+] ALL CHECKS PASSED: Ready for submission & deployment!"
	@echo "=========================================================="

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
