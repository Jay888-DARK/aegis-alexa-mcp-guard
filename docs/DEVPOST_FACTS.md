# Devpost Submission Fact Sheet

This document records the empirical, unvarnished facts, test results, and codebase verifications for the **Aegis** Devpost submission.
Every number is taken from actual test runs, log outputs, and source code citations. No estimates, approximations, or unverified claims are included.

---

## 1. Automated Test & Verification Commands

| Command | Status / Result | Exact Numbers & Details |
|---|---|---|
| `pytest -v` | **PASS** | **99 passed, 0 failed** in 31.4s across all test suites (`tests/` and `packages/aegis-guard/tests/`). (Includes 4 dedicated session-bypass penetration tests). |
| `python apps/aegishome/evals/run_evals.py` (Mode: Aegis) | **PASS** | **69 / 69 passed** (100.0% safety benchmark):<br>• Unsafe attacks blocked: **60 / 60** (100.0%)<br>• Safe actions allowed: **9 / 9** (0.0% false block rate). |
| `python apps/aegishome/evals/run_evals.py` (Mode: Baseline) | **PASS** | Scripted baseline executes 100% of attacks (**60 / 60**) and allows 100% of safe operations (**9 / 9**). (Explicitly labeled as scripted baseline, not a live LLM). |
| `python scripts/smoke_test.py` (default mode) | **PASS (with 1 skipped)** | **11 passed, 0 degraded, 0 failed, 1 skipped**.<br>Check 12 (Live Bedrock) was skipped because `AEGIS_LIVE_BEDROCK!=1`. |
| `python -m aegis_guard verify-audit --db aegis.db` | **PASS** | **Integrity verified (SHA-256 HMAC intact)**.<br>Total entries: 2. Chain Status: OK. Zero tampering detected. |

---

## 2. Evaluation Report Metrics (`EVAL_REPORT.md`)

| Metric | Exact Value | Source / Notes |
|---|---|---|
| **Attacks executed by scripted baseline** | **60 / 60 (100.0%)** | Scripted naive baseline blindly forwarded all 60 attacks without guardrails. |
| **Attacks executed with Aegis** | **0 / 60 (0.0%)** | All 60 malicious / unsafe attack payloads were caught and blocked. |
| **Aegis attacks blocked (Defense Rate)** | **60 / 60 (100.0%)** | 100% defense rate across all 9 threat categories. |
| **Safe actions allowed (Legitimate)** | **9 / 9 (100.0%)** | 8 benign operations + 1 authorized confirmation flow. |
| **Safe actions wrongly blocked (False Block Rate)** | **0 / 9 (0.0%)** | Zero false alarms on legitimate smart home queries & operations. |

---

## 3. Amazon Bedrock Status & Live API History

| Attribute | Recorded Value |
|---|---|
| **Model ID Tested** | `anthropic.claude-3-haiku-20240307-v1:0` (from `.env`) |
| **AWS Region** | `ap-southeast-2` |
| **Probe Ping Result** | **FAIL (`ResourceNotFoundException`)** via `scripts/bedrock_ping.py` |
| **Exact Error Message** | `"This model version has reached the end of its life. Please refer to the AWS documentation for more details."` (Latency: `2234.7 ms`) |
| **Has any live Bedrock call ever succeeded in this repo's logs?** | **NO**. Every live Bedrock invocation against AWS endpoints in this repo has failed due to daily token quota limits (`ThrottlingException`) or retired model versions (`ResourceNotFoundException`). All application and agent runs safely fell back to the deterministic rule engine. |

---

## 4. Architectural & Codebase Truth Verification (YES / NO)

| Verification Question | Answer | File & Line Citation | Exact Verification Details |
|---|:---:|---|---|
| **a) The confirmation code is stripped from any tool result before it reaches the model.** | **YES** | [apps/aegishome/agent.py:175-181](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/apps/aegishome/agent.py#L175-L181) | `sanitized_output = dict(tool_output)`<br>`sanitized_output.pop("voice_code", None)`<br>`sanitized_output.pop("code", None)`<br>The confirmation code is stripped so the model cannot read or parrot it back. |
| **b) The model has no tool that can owner-approve.** | **YES** | [apps/aegishome/agent.py:108-117](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/apps/aegishome/agent.py#L108-L117) | `EXPOSED_TOOLS = {"get_home_status", "propose_action", "read_visitor_note", "confirm_action"}`.<br>Tools exposed to the LLM explicitly exclude `approve_action` (`if name not in EXPOSED_TOOLS or name == "approve_action": continue`). Only the caregiver phone card / out-of-band channel can approve. |
| **c) `read_visitor_note` output is wrapped as untrusted data.** | **YES** | [apps/aegishome/src/aegishome/tools.py:158-164](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/apps/aegishome/src/aegishome/tools.py#L158-L164)<br>[packages/aegis-guard/src/aegis_guard/taint.py:65-72](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/packages/aegis-guard/src/aegis_guard/taint.py#L65-L72) | `get_taint_tracker().wrap_untrusted(raw_note["content"], source="visitor_note")`.<br>Wraps content inside `<untrusted_visitor_note>...</untrusted_visitor_note>` and taints the session in the DB. |
| **d) Proxy mode and a second upstream server exist and work.** | **NO** | N/A | `apps/aegis_proxy/` and `apps/upstream_calendar/` are planned future roadmap items and are not implemented in the current codebase. |
| **e) Tool-description pinning exists.** | **NO** | N/A | Pinning upstream tool description hashes against runtime prompt injection is not implemented in the current codebase. |
| **f) A held-out (model-generated) attack set was run.** | **NO** | [apps/aegishome/evals/cases.jsonl:1-69](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/apps/aegishome/evals/cases.jsonl#L1-L69) | All 69 test cases in `cases.jsonl` were human-authored by the project author to map to specific threat categories, rather than generated by a red-teaming LLM. |

---

## 5. MCP Protocol & SDK Versions

| Component | Version | Verification Source |
|---|---|---|
| **Negotiated MCP Protocol Version** | **`2025-11-25`** | Verified via Check 02 of `scripts/smoke_test.py` during client-server handshake over Streamable HTTP (`/mcp`). |
| **MCP SDK Version (Project Specification)** | **`mcp==1.28.0`** | Strictly pinned in [apps/aegishome/pyproject.toml:16](file:///c:/Users/HP/OneDrive/Desktop/Amazon%20Hackathon/apps/aegishome/pyproject.toml#L16) to match the verified virtualenv environment. |

---

## 6. Recommendations for Devpost Submission Text

Based on the empirical findings above, here are the verified numbers for your submission description:
1. **Pytest test count**: **99 pytest tests** (99 passed, 0 failed).
2. **Baseline comparison**: You can state: *"We compare Aegis against a scripted naive baseline with no guardrails across 69 test cases. The scripted baseline executed 60/60 attacks (100% compromise), while Aegis blocked 60/60 attacks (100% defense) with 0 false blocks on legitimate operations. A visual comparison chart is generated at `docs/baseline_vs_aegis.svg` and full details are documented in `EVAL_REPORT.md`."*
3. **Honesty rule**: Note that the baseline is a deterministic script, not a commercial LLM, and the 69 cases were author-crafted.
4. **Roadmap alignment**: Keep proxy mode, tool-description pinning, and model-generated attack sets under **"What's next"**.
