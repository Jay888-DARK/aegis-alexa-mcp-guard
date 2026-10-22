# Developer Friction Log: Alexa+ MCP & AWS Bedrock Integration

> This log documents concrete technical friction points, SDK quirks, protocol negotiation edge cases, and architectural hurdles encountered while building **Aegis** with the official Python `mcp` SDK, Starlette, and AWS Bedrock Converse API. Each entry includes reproduction steps, impact severity, workarounds, and actionable recommendations for SDK authors.

---

## Index of Friction Entries

1. **[MCP-01]** MCP Python SDK Streamable HTTP Sub-App Lifespan Not Initialized in Parent Starlette
2. **[MCP-02]** Date-Based Protocol Revisions Fail PEP 440 `packaging.version.parse`
3. **[AWS-01]** Amazon Bedrock Converse API Offline / CI Testing Pattern
4. **[MCP-03]** Starlette Route Ordering Conflict Between Catch-All Streamable HTTP Mount and REST/UI Endpoints
5. **[AWS-02]** Daily Token Quota ThrottlingException on High-Tier Foundation Models
6. **[MCP-04]** Streamable HTTP AnyIO Worker Task ContextVar Isolation for Session Binding
7. **[LLM-01]** Bedrock Zero-Quota Sandbox Limits Bypassed via Dual Groq/Bedrock Tool-Calling Fallback

---

## Detailed Entries

### [MCP-01] Streamable HTTP Sub-App Lifespan Not Initialized in Parent Starlette

- **Component**: `mcp.server.streamable_http.StreamableHTTPServerTransport` / Starlette
- **Task**: Mount an MCP Server exposing Streamable HTTP at `/mcp` inside a unified parent Starlette application alongside `GET /health` and static UI routes.
- **Steps to Reproduce**:
  1. Initialize `mcp_server = MCPServer("aegishome")` and obtain the Starlette sub-application via `mcp_app = mcp_server.streamable_http_app(streamable_http_path='/mcp')`.
  2. Mount `mcp_app` inside a parent `Starlette(routes=[Route('/health', ...), Mount('', app=mcp_app)])`.
  3. Send an MCP initialize POST request to `/mcp`.
- **Expected vs Actual**:
  - *Expected*: The streamable HTTP session manager should process incoming requests immediately.
  - *Actual*: Server raises `RuntimeError: Task group is not initialized. Make sure to use run().` and returns an HTTP 500 error because Starlette does not automatically run child sub-application lifespans when mounted.
- **Severity**: High (Server crashes on first initialization request)
- **Workaround**: Explicitly bind and enter the child MCP application's router lifespan context within the parent Starlette application's lifespan handler:
  ```python
  @contextlib.asynccontextmanager
  async def lifespan(app: Starlette):
      async with mcp_app.router.lifespan_context(mcp_app):
          yield
  ```
- **Suggestion**:
  - Document this sub-application mounting pattern explicitly in the official Python MCP SDK README and documentation.
  - Alternatively, provide a convenience method such as `mcp_server.create_starlette_app(additional_routes=[...])` that manages the lifespan context internally.

---

### [MCP-02] Date-Based Protocol Revisions Incompatible with `packaging.version.parse`

- **Component**: `mcp.types.LATEST_PROTOCOL_VERSION` (`2025-11-25`, `2026-07-28`)
- **Task**: Verify in automated test suites and gateway policy that a client-negotiated protocol version meets minimum requirements (e.g., `>= 2025-11-25`).
- **Steps to Reproduce**:
  1. Complete initialization handshake: `init_res = await session.initialize()`.
  2. Attempt to parse `init_res.protocol_version` using standard Python tooling:
     ```python
     from packaging.version import parse
     parsed = parse(init_res.protocol_version)
     ```
- **Expected vs Actual**:
  - *Expected*: Version string parsed into an ordered version object.
  - *Actual*: Raises `packaging.version.InvalidVersion: Invalid version: '2025-11-25'` because MCP uses ISO calendar date revisions (`YYYY-MM-DD`) rather than PEP 440 semantic version numbers.
- **Severity**: Medium (Breaks standard version comparison utilities)
- **Workaround**: Rely on lexicographical string comparison on ISO-formatted strings (`negotiated >= "2025-11-25"`) or use the internal `mcp.server.streamable_http.is_version_at_least()` helper.
- **Suggestion**:
  - Expose a public, first-class `is_version_at_least(version_str, minimum_str) -> bool` function in `mcp.types`.
  - Clarify in the MCP Specification how non-standard version comparison should be implemented by compliant hosts and gateways.

---

### [AWS-01] Amazon Bedrock Converse API Offline / CI Testing Pattern

- **Component**: `boto3` Bedrock-Runtime (`Converse` API)
- **Task**: Test LLM status summarization, prompt sandboxing, and numeric hallucination guardrails in continuous integration environments without requiring live AWS credentials or incurring API costs.
- **Steps to Reproduce**:
  1. Implement Bedrock tool invocation: `client = boto3.client("bedrock-runtime")`.
  2. Run `pytest` in an uncredentialed CI runner or offline development environment.
- **Expected vs Actual**:
  - *Expected*: Unit tests should be able to validate prompt structures and test guardrail violation handling deterministically.
  - *Actual*: Calls raise `botocore.exceptions.NoCredentialsError` unless valid AWS credentials exist.
- **Severity**: Low (Developer workflow & CI constraint)
- **Workaround**: Design an explicit `LLMModel` protocol and implement a configurable `FakeModel` test double supporting:
  - `FakeModel.accurate()`: Returns factual device state drafts.
  - `FakeModel.hallucinating_package(val)`: Synthesizes ungrounded numeric values to test deterministic fallback paths.
  - `FakeModel.failing()`: Injects simulated network/API exceptions to verify graceful degradation.
- **Suggestion**:
  - AWS SDK documentation should highlight recommended mock/stub patterns for Bedrock Converse tool-use workflows to encourage test-driven guardrail development.

---

### [MCP-03] Starlette Route Ordering Conflicts with Catch-All Streamable HTTP Mount

- **Component**: Starlette Routing Engine & MCP Streamable HTTP Router
- **Task**: Co-locate custom REST management endpoints (`/api/say`, `/api/state`, `/api/approve`, `/api/wire_log`) and static web UI assets on the same port as the MCP Streamable HTTP transport.
- **Steps to Reproduce**:
  1. Define routes: `routes = [Mount("", app=mcp_app), Route("/api/state", ...), Mount("/static", ...)]`.
  2. Send a `GET /api/state` request.
- **Expected vs Actual**:
  - *Expected*: `/api/state` matches the route handler.
  - *Actual*: The empty prefix `Mount("", app=mcp_app)` captures all incoming HTTP paths and forwards them to the MCP sub-application router, returning HTTP 404 for non-MCP paths.
- **Severity**: Medium (Silent route shadowing)
- **Workaround**: Strictly enforce route declaration precedence in Starlette: specific REST API routes and `/static` mount MUST be defined before the root `Mount("", app=mcp_app)`.
- **Suggestion**:
  - Clarify in multi-transport examples that empty-prefix mounts in Starlette act as greedy catch-alls and should be placed at the end of the routing table.

---

### [AWS-02] Daily Token Quota ThrottlingException on High-Tier Foundation Models

- **Component**: AWS Bedrock Runtime (`Converse` API) / Model Quotas
- **Task**: Execute multi-turn tool-use agent conversational turns in sandbox / evaluation accounts using high-tier foundation models.
- **Steps to Reproduce**:
  1. Configure `BEDROCK_MODEL_ID` to a heavy/standard model.
  2. Send consecutive tool-use turns with full conversation history and extensive system prompt.
  3. Model returns `ClientError: An error occurred (ThrottlingException) when calling the Converse operation: Too many requests. Rate limit exceeded or daily token quota reached.`
- **Expected vs Actual**:
  - *Expected*: The agent processes caregiver requests or gracefully fails over to alternative models without disrupting smart home safety.
  - *Actual*: Raw `ThrottlingException` halts execution, causing the smart home assistant to crash or become unresponsive if unhandled.
- **Severity**: High (Total system outage for cloud-dependent agents)
- **Workaround**: Implement a 3-tier resilient architecture:
  1. **Token Savings**: Cap `maxTokens=300`, `temperature=0.2`, prune history to the last 6 turns, and compress the system prompt.
  2. **Exponential Backoff with Jitter**: Automatically retry up to 2 times on `ThrottlingException` before switching tiers.
  3. **Multi-Tier Model Failover**: Configure `BEDROCK_FALLBACK_MODEL_ID` (targeting lighter models with higher quotas, such as Amazon Nova Micro or Claude Haiku) and seamlessly fall back to an offline deterministic rule engine if all Bedrock tiers are throttled.
- **Suggestion**:
  - Provide automated multi-model routing / fallback capabilities directly within the Bedrock client SDK or Converse API configuration.

---

### [MCP-04] Streamable HTTP AnyIO Worker Task ContextVar Isolation for Session Binding

- **Component**: `mcp.server.streamable_http` / `mcp.server.fastmcp.server` / AnyIO TaskGroup
- **Task**: Reliably extract and bind client `Mcp-Session-Id` transport headers to ambient server context so that tool handlers (`propose_action`, `confirm_action`) can enforce taint tracking and session isolation without requiring callers to pass spoofable `session_id` arguments.
- **Steps to Reproduce**:
  1. Mount an MCP Streamable HTTP app in Starlette wrapped with ASGI middleware setting a Python `ContextVar` (`_CURRENT_SESSION_ID.set(mcp_session_id)`).
  2. The client connects and performs an initial handshake, spawning the internal `app.run` worker task.
  3. Subsequent POST requests invoke tool handlers.
- **Expected vs Actual**:
  - *Expected*: The tool handler reads the ambient `ContextVar` set by ASGI middleware during the current HTTP request.
  - *Actual*: In FastMCP/Streamable HTTP, the server runs as an independent long-running worker task spawned during session creation. Context variable modifications in the HTTP request task do not propagate across AnyIO memory object streams to the pre-existing server task, causing the tool handler to observe `ContextVar.get() is None`.
- **Severity**: High (Triggers fail-closed fallback or breaks session-bound security controls)
- **Workaround**: Query `mcp.server.lowlevel.server.request_ctx` directly from within the tool execution context. During request dispatch, `Server._handle_request` sets `request_ctx` with `ServerMessageMetadata.request_context` (the underlying Starlette `Request`), allowing reliable extraction of `request.headers.get("mcp-session-id")`.
- **Suggestion**:
  - FastMCP should natively expose the authoritative session ID on `Context` (e.g. `context.session_id`) to all registered tool functions.

---

### [LLM-01] Bedrock Zero-Quota Sandbox Limits Bypassed via Dual Groq/Bedrock Tool-Calling Fallback

- **Component**: AWS Bedrock Runtime Quota Management / Multi-Cloud Fallback Architecture
- **Task**: Run live, interactive AI agent tool-calling demonstrations and automated red-teaming evaluations in AWS accounts where foundation model quotas are pending approval or set to zero.
- **Steps to Reproduce**:
  1. Attempt live Bedrock Converse calls (`anthropic.claude-3-haiku-20240307-v1:0` or `meta.llama3-70b-instruct-v1:0`) in a new or restricted AWS account.
  2. Boto3 raises `AccessDeniedException` or `ThrottlingException: daily token quota reached` with zero quota allocated.
- **Expected vs Actual**:
  - *Expected*: Live demo can interactively parse spoken caregiver intent and execute MCP tool calling.
  - *Actual*: Zero-quota block prevents the live AI backend from executing.
- **Severity**: Critical (Blocks live evaluation and video demonstration)
- **Workaround**: Implement an extensible primary active tier (`GroqClient`) supporting ultra-high-throughput tool calling (`llama-3.1-70b-versatile`) mapped 1:1 to MCP tool schemas, with automatic fallback:
  $$\text{GROQ} \longrightarrow \text{BEDROCK} \longrightarrow \text{DETERMINISTIC RULE ENGINE}$$
  The API key is strictly sourced from `GROQ_API_KEY` (never hardcoded, `.env` gitignored), allowing live video demonstration with zero cloud quota friction.
- **Suggestion**:
  - AWS Bedrock sandbox accounts should provision a baseline starter token quota for hackathon developers to enable prototyping without manual quota increase requests.


