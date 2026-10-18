# MCP Shield — Zero-Trust Gateway for AI Agents & MCP Tool Servers

MCP Shield is a zero-trust gateway and reverse-proxy Policy Enforcement Point (PEP) paired with an OAuth 2.1 Authorization Server. It enforces strictly scoped, audience-bound access between autonomous AI agents and Model Context Protocol (MCP) tool servers.

---

## Zero-Trust Principles Enforced
1. **No Standing Agent Credentials**: Agents only receive short-lived (5-minute), audience-bound, task-bound JWTs.
2. **Strict Audience Binding (RFC 8707)**: Tokens issued for MCP Server A (e.g. GitHub Copilot MCP) are cryptographically bound and strictly rejected when presented to MCP Server B (e.g. Slack MCP).
3. **Task & Intent Binding**: Every token permanently encodes the user's original instruction (`task_id`) and delegation context (`act`).
4. **Mandatory PKCE (RFC 7636)**: Public AI agents must use S256 PKCE code challenges; implicit and plain methods are rejected.
5. **Fail-Closed Policy Enforcement**: Any unauthenticated, expired, or audience-mismatched call fails closed with RFC 9728 discovery hints.
6. **Immutable Audit Logging**: Every gateway request writes a structured JSON line to `access.log` with SHA-256 argument hashing and zero token/secret leakage.

---

## Phase 1 Deliverables Summary
- **OAuth 2.1 Authorization Server**:
  - `POST /oauth/register`: RFC 7591 Dynamic Client Registration for AI agents.
  - `GET /oauth/authorize`: Authorization code flow with mandatory S256 PKCE, RFC 8707 Resource Indicators, and task context.
  - `POST /oauth/token`: Exchanges code + PKCE verifier for an RS256-signed JWT (5-minute lifetime).
  - `GET /.well-known/jwks.json`: Exposes RFC 7517 public keys with key ID (`kid`).
  - `GET /.well-known/oauth-protected-resource`: Exposes RFC 9728 Protected Resource Metadata.
  - `GET /.well-known/oauth-authorization-server`: Exposes RFC 8414 OAuth 2.0 metadata.
  - `POST /oauth/revoke`: RFC 7009 token revocation.
  - `POST /oauth/introspect`: RFC 7662 token introspection.
- **Protected Resource PEP**:
  - `GET /mcp/resource-test`: Demonstrates the 401 + `WWW-Authenticate: Bearer resource_metadata="..."` discovery flow and validates audience binding.
- **Audit Logging Module**:
  - `src/mcp_shield/logging.py`: Structured JSON logger writing to `access.log` using `RotatingFileHandler`.
  - Arguments are hashed with SHA-256. Zero credential leakage.
- **Relational & Ephemeral Storage**:
  - PostgreSQL schema for `users`, `clients`, `oauth_sessions`, and `issued_tokens` with Alembic migration (`0001_initial_schema`).
  - Redis cache with in-memory fallback for authorization codes and instant revocation checking.
  - SQLite auto-fallback for offline zero-friction development and automated testing.
- **Decisions Log**:
  - `decisions.md` initiated with entries D-001 through D-006.

---

## Running & Testing

### 1. Prerequisites
- Python 3.12+ (or Python 3.14 via `uv`)
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Docker & Docker Compose (optional, for Postgres + Redis)

### 2. Install Dependencies
```bash
uv sync
```

### 3. Start Database & Redis (Optional Docker Compose)
```bash
docker compose up -d
```
*Note: If PostgreSQL and Redis are not running, MCP Shield automatically falls back to local SQLite and in-memory caching so development and testing run out of the box.*

### 4. Run Database Migrations
```bash
uv run alembic upgrade head
```

### 5. Start the Gateway Server
```bash
uv run uvicorn mcp_shield.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation will be accessible at:
- Swagger UI: `http://localhost:8000/docs`
- Protected Resource Metadata: `http://localhost:8000/.well-known/oauth-protected-resource`
- Authorization Server Metadata: `http://localhost:8000/.well-known/oauth-authorization-server`
- JWKS Public Keys: `http://localhost:8000/.well-known/jwks.json`

### 6. Run the Automated Test Suite
```bash
uv run pytest -v
```
The test suite validates:
- Dynamic Client Registration (RFC 7591)
- PKCE failures rejection (missing challenge, plain method, wrong verifier)
- 5-minute token expiry and expiration rejection
- RFC 8707 audience binding: token for Resource A rejected for Resource B
- RFC 7009 token revocation and RFC 7662 introspection
- RFC 9728 discovery flow (401 + WWW-Authenticate header)
- Zero secret leakage in `access.log` (asserts no tokens, secrets, PATs, or verifiers appear in logs)
- Full end-to-end lifecycle integration

### 7. Run the Standalone End-to-End Demo Script
You can execute the 12-step full lifecycle demonstration against a running server or standalone:
```bash
uv run python scripts/demo_flow.py
```

---

## Phase 2 Deliverables Summary
- **Reverse Proxy Policy Enforcement Point (PEP)**:
  - `POST /mcp/proxy`: End-to-end zero-trust gateway for Streamable HTTP MCP servers.
  - Transparent credential swapping: agent bearer token is verified and stripped; upstream fine-grained PAT is injected only after policy approval.
  - Streamed response handling: full support for SSE (`text/event-stream`), `mcp-session-id` lifecycle, and error mapping for GitHub 403 / 429 rate limits.
- **Real Remote GitHub Copilot MCP Integration**:
  - Live discovery: queried `tools/list` on `https://api.githubcopilot.com/mcp/` and cataloged all 46 tools.
  - Scoped to throwaway repository: `shreenithi23/mcp-shield-test`.
- **Credential Vault with Envelope Encryption**:
  - Dual-mode architecture: (a) fine-grained PAT scoped to test repo; (b) pluggable per-user OAuth tokens.
  - Envelope encryption using `FernetKMSProvider` (with KMS-ready interface `BaseKMSProvider`), generating random per-secret Data Encryption Keys (DEKs).
- **RFC 9449 DPoP Proof-of-Possession**:
  - Verification of DPoP proof signatures, `htm`/`htu` matching, `iat` freshness, and server nonces.
  - Token binding via `cnf.jkt` (JWK thumbprint matching).
  - Replay defense caching `jti` in Redis / EphemeralCache.
- **Three-Tier Policy Pipeline**:
  - **Layer 1 (RBAC)**: Admin roles (`admin`, `security_reviewer`, `developer`, `viewer`).
  - **Layer 2 (PBAC in OPA/Rego)**: Declarative Rego policies checking `server:tool:action`, repository argument constraints (`owner`, `repo`), and enforcing the rule that users can only delegate permissions they hold.
  - **Layer 3 (Quotas & Circuit Breaker)**: Sliding-window rate limits (calls/min, writes/hour, records/day) and circuit breaker that trips after 5 consecutive denials, returning HTTP 429.
- **RFC 9396 & RFC 8693 Token Exchange**:
  - Structured `authorization_details` in tokens.
  - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` for downscoping parent tokens per task.

---

- **OpenJev System One Decision Engine ([GPT-AGI/OpenJev](https://github.com/GPT-AGI/OpenJev))**:
  - Direct integration of the `openjev` library for typed decisions (`Noul`, `Choice`, `Score`).
  - `OpenJevProvider`: Executes typed System One decisions via `openjev.core.primitives.SystemOneRequest`.
  - Single forward-pass probability evaluation reading token logits at the answer position.
  - Zero mock decisions: All evaluations flow through OpenJev primitives with normalized entropy confidence.
- **Three Strategic Checkpoints**:
  1. *Tool Call (Pre-execution)*: Evaluates `intent_match`, `overreach`, `reversibility`.
  2. *Tool Result (Post-execution)*: Evaluates `injection_risk`, `sensitivity`.
  3. *Tool Registration / Change*: Evaluates `poisoning_risk`, `semantic_drift`.
- **Layer 4 ABAC (OPA/Rego) & Four Explicit Outcomes**:
  - **`allow`**: Auto-allow reads and reversible writes meeting calibrated confidence thresholds.
  - **`allow_narrower`**: Modifies arguments (e.g. clamps excessive row `limit` to 10 or paginates) to minimize blast radius.
  - **`hold`**: Holds tool call for human authorization approval (Tier 3 irreversible tools, write timeouts, tainted sessions, or borderline confidence). Returns HTTP `202 Accepted` (`status: "hold_for_approval"`).
  - **`deny`**: Hard denial for static policy violations, severe intent mismatches (<0.50), or prompt injections (>0.50). Returns HTTP `403 Forbidden`.
- **46 GitHub MCP Tools Classification**:
  - *Tier 1 (Read-Only)*: 28 tools (`list_issues`, `issue_read`, `search_code`, etc.).
  - *Tier 2 (Reversible Write)*: 12 tools (`create_issue`, `update_issue`, `create_pull_request`, etc.).
  - *Tier 3 (Irreversible / Privilege)*: 6 tools (`delete_file`, `push_files`, `merge_pull_request`, etc. - always held for human approval).
- **Fail-Safe 150ms Timeout**:
  - Reads fall back to static policy allow if the model times out.
  - Writes fail closed and are held for human approval (`model_timeout_write_held`).
- **Session Tainting**:
  - Tool outputs with `injection_risk >= 0.50` taint the MCP session in cache for 1 hour. Subsequent writes in the session are held for approval.
- **Audit Logging**:
  - Every decision records `scores` (calibrated probabilities, model name/version, decision latency) and `outcome` in `access.log`.

---

## Running & Testing

### 1. Prerequisites
- Python 3.12+ (or Python 3.14 via `uv`)
- `uv` package manager
- `opa` Open Policy Agent binary (`brew install opa`)
- Docker & Docker Compose (optional, for Postgres + Redis)

### 2. Environment Configuration
Create a local `.env` file (git-ignored):
```bash
GITHUB_PAT="github_pat_..."
GITHUB_TEST_REPO="shreenithi23/mcp-shield-test"
```

### 3. Run Automated Tests
Run the complete unit and integration test suite (43 passing tests across all 4 phases):
```bash
uv run pytest -v
```

Run OPA Rego policy unit tests (8 passing tests):
```bash
opa test src/mcp_shield/policies/ -v
```

### 4. Run Phase 4 Live End-to-End Demo Script
Execute the full runtime defenses and human-in-the-loop flow against the REAL remote GitHub MCP server:
```bash
uv run python scripts/phase4_e2e_demo.py
```

The script executes and validates the exact outcome sequence:
1. `summarize bugs` on `shreenithi23/mcp-shield-test` via real GitHub Copilot MCP.
2. `injected issue detected` via Checkpoint 2 AI analysis.
3. `session tainted` & token automatically exchanged via RFC 8693 for read-only tools.
4. `Slack post held` for out-of-band CIBA human approval (with plain-English explanation).
5. `escalation denied` strictly blocking unauthorized writes (`create_or_update_file`).
6. `tool integrity rug-pull blocked` on local malicious server via SHA-256 hash pinning.
7. Verification of all structured audit events in `access.log` in exact chronological order.

---

## Decisions Log
The following architectural choices have been recorded in [`decisions.md`](./decisions.md):
- **D-001**: Cryptographic Engine & OAuth 2.1 Token Implementation (Authlib + Cryptography RS256)
- **D-002**: Key Generation and JWKS Rotation Strategy (RS256 with deterministic `kid` & JWKS export)
- **D-003**: Dual Storage Architecture (PostgreSQL for durability + Redis for ephemeral state)
- **D-004**: Audit & Access Logging with Nonce/Secret Redaction (JSON lines to `access.log` with SHA-256 argument hashing)
- **D-005**: Upstream Identity Provider Integration & Local Mock IdP (Pluggable OIDC with Mock dev provider)
- **D-006**: Strict Audience Binding via RFC 8707 Resource Indicators (Single-resource bound `aud` claim)
- **D-007**: Upstream Credential Strategy (Fine-Grained PAT vs GitHub OAuth App)
- **D-008**: Envelope Encryption for Credential Vault (Fernet KEK with In-Memory DEK, KMS-Ready Interface)
- **D-009**: DPoP Proof-of-Possession and Replay Defense Architecture (RFC 9449)
- **D-010**: Three-Tier Policy Enforcement Architecture (RBAC, OPA/Rego PBAC, Quotas & Circuit Breaker)
- **D-011**: Fail-Closed Behavior on Ephemeral Storage / Redis Outage
- **D-012**: Adoption of OpenJev as the System One Decision Engine
- **D-013**: Model Never Overrides Static Authorization Denial
- **D-014**: Fail-Safe 150ms Timeout: Read Fallback vs. Write Fail-Closed
- **D-015**: Four Explicit Authorization Outcomes: Allow, Allow Narrower, Hold, Deny
- **D-016**: Session Tainting via Checkpoint 2 Prompt Injection Detection
- **D-017**: Taint Tracking Lifecycle, Clearing Rules, and RFC 8693 Token Downscoping
- **D-018**: CIBA Out-of-Band Approval Flow (Slack Block Kit & Mobile Web App)
- **D-019**: Sensitivity Criteria for Step-Up Multi-Factor Authentication (TOTP / WebAuthn)
- **D-020**: Generation and Scope of Plain-English Explanations
- **D-021**: Tool Integrity SHA-256 Description Pinning, Drift Detection, and Quarantine
