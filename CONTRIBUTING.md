# Contributing to Aegis

Thank you for your interest in contributing to Aegis! Aegis is an open-source, deterministic safety gateway and MCP server designed to protect vulnerable adults in smart home environments from adversarial prompt injections, excessive actuator commands, and unauthorized access.

---

## Repository Architecture

This mono-repo consists of two primary packages:
- **`packages/aegis-guard`**: Deterministic Python safety interceptor, policy engine, audit logger, and taint tracker for Model Context Protocol (MCP) tool execution.
- **`apps/aegishome`**: The Alexa+ smart-home caregiver MCP server, Bedrock multi-tier agent, and real-time dashboard UI.

---

## Development Setup

### Prerequisites
- Python **>= 3.11**
- `git`
- (Optional) AWS account with Amazon Bedrock access if testing live Bedrock models

### Quickstart

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/aegis.git
   cd aegis
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies in editable mode:**
   ```bash
   make install
   # or on Windows:
   .\make.ps1 install
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your Bedrock model IDs and AWS region if testing live endpoints
   ```

---

## Verification & Test Commands

Before opening a pull request or submitting code, please ensure all checks pass:

| Command | PowerShell Equivalent | Purpose |
|---------|-----------------------|---------|
| `make check-secrets` | `.\make.ps1 check-secrets` | Scans repository for leaked AWS keys, tokens, or credentials |
| `make test-unit` | `pytest -v` | Runs unit & integration test suites (95+ tests) |
| `make evals` | `.\make.ps1 evals` | Runs the 61-case adversarial red-teaming evaluation benchmark |
| `make smoke` | `.\make.ps1 smoke` | Runs the end-to-end integration smoke test |
| `make demo` | `.\make.ps1 demo` | Launches local caregiver dashboard on `http://127.0.0.1:8000` |
| `make all-checks` | `.\make.ps1 all-checks` | Runs the complete quality, security, and safety test matrix |

---

## Pull Request Guidelines

1. **Keep Safety Logic Isolated**: Deterministic safety checks belong in `packages/aegis-guard`. Smart home device tools and agent reasoning belong in `apps/aegishome`.
2. **Never Weaken Default Policies**: Safety policies (`enforce` mode) must block unauthorized high-risk physical actions (e.g. unlocking doors, extreme temperature changes) without authenticated confirmation.
3. **Add Tests for New Features**: Any new policy, guard rule, or tool must have unit tests in `tests/` and pass red-teaming evals in `evals/`.
4. **No Secrets**: Never commit `.env` files, AWS credentials, bearer tokens, or API keys. Always run `make check-secrets`.
