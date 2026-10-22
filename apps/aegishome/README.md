# AegisHome

Smart-home caregiver MCP server for Alexa+.

## Overview
Exposes smart home device controls, resident status, and caregiver tools over the official Model Context Protocol (MCP) Streamable HTTP transport at `/mcp`, protected by Aegis Guard policy enforcement.

## Exposed Tools
1. `get_home_status`: Returns current smart home states (resident vital signs, locks, HVAC temperature, appliances, medication drawer).
2. `propose_action`: Initiates a proposal to execute a smart device operation (e.g., unlocking doors, setting temperatures).
3. `confirm_action`: Confirms or rejects a proposed action with caregiver authorization and audit justification.
4. `read_visitor_note`: Reads notes left by external visitors/couriers at the door (tagged as untrusted input).

## Running the Server
```bash
python -m aegishome.main --host 127.0.0.1 --port 8000
```

## Running Tests
```bash
pytest -v tests/
```

## MCP Inspector Connection
Connect via `@modelcontextprotocol/inspector` using Streamable HTTP at `http://127.0.0.1:8000/mcp`.
