# Security Policy & Threat Model

Aegis is built with a defense-in-depth philosophy specifically designed to safeguard smart home environments, physical actuators, and vulnerable individuals against adversarial prompt injections and autonomous LLM misbehavior.

---

## 1. Reporting a Vulnerability

We take the security of Aegis very seriously. If you discover a security vulnerability or bypass in our deterministic safety filters or MCP gateway:

- **Do NOT create a public GitHub issue.**
- Please email the repository maintainer directly at: **`jay.b@ahduni.edu.in`** with:
  - Description of the vulnerability and attack vector
  - Minimal reproducible example or prompt transcript
  - Impact assessment (e.g., unauthorized actuator execution, policy bypass, taint evasion)
- **Response Timeline:** You will receive an initial response within 48 hours, followed by regular status updates as patches are verified and released.

---

## 2. Threat Model Summary

Aegis assumes that LLMs (Large Language Models) are **probabilistic, inherently jailbreakable, and vulnerable to indirect prompt injection**. Therefore, security boundaries must be enforced **deterministically at the tool execution interceptor layer**, not merely via model system prompts.

```
       [ External Untrusted World ]
       (Visitor notes, porch deliveries, ambient speech)
                     │
                     ▼
       [ LLM Reasoning Layer (Bedrock Agent) ]
       (Probabilistic, vulnerable to indirect prompt injection)
                     │
                     ▼ (Tool Use Call)
   ====================================================
   [ Aegis Guard Deterministic Safety Gateway ]  ◄── ENFORCEMENT BOUNDARY
   ----------------------------------------------------
   1. Taint Tracking: Marks context as tainted upon reading untrusted input
   2. Numeric Bounds: Prevents dangerous thermostat / sensor values
   3. Policy Matrix: Blocks high-risk actions without explicit approval
   4. Human-in-the-Loop: Requires caregiver-authenticated voice confirmation
   ====================================================
                     │
                     ▼ (Sanitized & Confirmed Action)
       [ Smart Home Actuators & Physical Devices ]
       (Front door locks, alarms, HVAC, emergency contact)
```

### Key Trust Boundaries:

1. **Untrusted Sensory Inputs (`<untrusted_visitor_note>`)**: Notes left by delivery drivers, visitors, or callers are treated as hostile external data.
2. **Context Taint Analysis**: Once untrusted content is read into the session history, the session is marked as `TAINTED`. High-risk tool proposals originating from tainted context are flagged with elevated scrutiny.
3. **Deterministic Actuator Gateways**: Physical actions are partitioned into:
   - **Low-Risk Read / Status**: `get_home_status`, `read_visitor_note` (allowed freely).
   - **Safe Actuators**: setting temperature within comfortable bounds (65°F - 78°F).
   - **High-Risk Physical Actuators**: `unlock_door`, `open_garage`, `disarm_security`. These **cannot** be executed directly by the model. The model can only `propose_action`, generating a cryptographically random voice confirmation code shown strictly on the caregiver's authenticated screen. The model cannot execute `confirm_action` until the human caregiver speaks or enters the code.
4. **Append-Only Tamper-Evident Audit Logging**: Every proposal, blocked action, and confirmation is logged to `aegis_audit.jsonl` with cryptographic timestamps and session IDs.

---

## 3. Known Limitations

- **Host Environment Security**: Aegis protects the MCP tool layer and model-actuator boundary. It assumes the underlying host operating system, Python runtime, and SQLite database file are not compromised at root level.
- **Physical Bypasses**: Software safety gates cannot prevent physical attacks on hardware (e.g. lock picking or physical tampering with smart plugs).
- **Network Boundaries**: In production, the MCP HTTP endpoint (`/mcp`) and Caregiver Dashboard (`/`) must be protected behind TLS and standard authentication (e.g., OAuth2 / mTLS) when exposed beyond localhost.
- **Model Quotas & Latency**: Under extreme AWS Bedrock API rate limits, Aegis seamlessly switches to secondary fallback models or the local deterministic rule engine. The deterministic rule engine guarantees 100% safety even when completely disconnected from the Internet.
