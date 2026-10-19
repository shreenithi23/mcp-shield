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
- **D-022**: Cryptographic Hash Chaining for Append-Only Audit Integrity
- **D-023**: Dual-Log Architecture and Continuous Bidirectional Reconciliation
- **D-024**: RBAC-Gated Admin Console Architecture (Admin, Operator, Auditor Hierarchy)
- **D-025**: Labeled Threat Benchmark Dataset and Model Calibration Criteria
- **D-026**: Frontend Architecture: React 19 + TypeScript (Vite) with Single-Page Plain CSS
- **D-027**: Polling vs. WebSockets: 2-Second HTTP Polling for Approvals Queue
- **D-028**: Read-Only /demo API Router for Live Presentation & Interactive Negative Testing

---

## Demo Frontend (React + TypeScript + Vite)

The frontend is a lightweight, zero-dependency-bloat Single Page Application built with **Vite, React 19, and TypeScript**. It connects to the live FastAPI backend to demonstrate all zero-trust PEP capabilities in a live presentation or walkthrough.

### Architecture Highlights:
- **No Complex Routing or State Libraries**: Pure React component state and plain CSS design tokens.
- **Strict Zero-Leakage Policy**: Decodes JWT claims in the browser client-side; never logs or displays token signatures, GitHub PATs, or client secrets.
- **Live Backend Data**: 100% of numbers, badges, audit chains, access logs, and evaluation metrics are sourced directly from live backend endpoints.
- **Standardized Color Semantics**: Green (`ALLOW`), Blue (`ALLOW NARROWER`), Amber (`HOLD`), Red (`DENY`), Crimson (`TAINTED`).

### Running the Full System Locally:

1. **Start Backend Gateway**:
   ```bash
   uv run uvicorn mcp_shield.main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. **Start Frontend Dev Server**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open your browser at `http://localhost:5173`. (Configured via `VITE_API_BASE_URL=http://localhost:8000` in `frontend/.env`).

---

## 2-Minute Live Demo Script (Numbered Clicks)

Follow this numbered click path for a seamless, end-to-end presentation of MCP Shield:

1. **Step 1: Authenticate and Register Agent**
   - On the top header, verify the session badge is green (`● SESSION NORMAL`).
   - On the **"1. Agent Run"** tab, click **"1. Login (OIDC + PKCE)"**. The current user (`Alice - Platform Engineer`) is authenticated and issued a DPoP-bound token.
   - Click **"2. Register Agent (DCR)"** to simulate RFC 7591 Dynamic Client Registration, registering `agent_copilot_assistant`.

2. **Step 2: Execute Prompt Injection Scenario**
   - Click scenario card **"(b) Injection: Real GitHub Issue Payload"**.
   - Click **"Run Scenario"**.
   - Observe the step-by-step execution timeline:
     - **Call #1 (`list_issues`)**: Returns `ALLOW`. AI Checkpoint 2 detects prompt injection (`injection_risk: 0.89`).
     - **Taint Event**: A prominent red banner triggers: `⚠️ SESSION STATE: TAINTED (READ-ONLY)`. RFC 8693 token exchange downscopes the token to Tier 1 read-only tools.
     - **Call #2 (`slack_post_message`)**: Status is amber `HOLD` (reason: `tainted_write_held`). Click **"Inspect"** to view model scores and the plain-English explanation.
     - **Call #3 (`create_or_update_file`)**: Status is red `DENY` (reason: `static_tool_not_granted_in_token`). Escalation blocked!

3. **Step 3: Resolve Held CIBA Approval**
   - Click tab **"3. Approvals"**.
   - The held `slack_post_message` call appears immediately in the queue (polled every 2s).
   - Review proposed arguments and explanation. Enter a 6-digit TOTP code (or leave blank for demo dev secret) and click **"Approve"**.
   - Notice the call is resolved and the queue clears.

4. **Step 4: Inspect Token Decoded Claims & Negative Tests**
   - Click tab **"2. Tokens"**.
   - Observe the live 5-minute countdown timer (`⏱ 4:58`).
   - Review decoded claims: single-resource `aud` (`https://api.githubcopilot.com/mcp/`), `cnf.jkt` thumbprint, and RFC 9396 `authorization_details`.
   - Click **"Try token on wrong server"**: Gateway returns `401 Unauthorized` with `Audience mismatch`.
   - Click **"Replay without DPoP key"**: Gateway returns `401 Unauthorized` with `Missing DPoP proof for bound token`.

5. **Step 5: Inspect Tool Integrity & Simulate Rug Pull**
   - Click tab **"4. Tools & Policy"**.
   - Review the table of approved tools with pinned SHA-256 hashes.
   - Click **"Simulate Rug Pull (Malicious Server)"**: The tool description mutates. MCP Shield flags the hash mismatch, displays elevated `poisoning_risk: 0.96`, and sets status to `QUARANTINED`.
   - Click **"Admin Re-Approve New Hash"** to demonstrate administrative unquarantine.

6. **Step 6: Cryptographic Audit Verification & Tampering Demo**
   - Click tab **"5. Logs & Results"** -> **"Cryptographic Audit Log"**.
   - Click **"Verify Chain"**: Gateway verifies every SHA-256 back-pointer and confirms green `INTEGRITY 100% (OK)`.
   - Click **"Tamper with Record"**: Simulates malicious file modification on disk. The chain instantly flags `CHAIN INTEGRITY COMPROMISED! (Hash mismatch detected)`.
   - Click **"Restore Chain"**: Restores pristine state and passes verification.

7. **Step 7: Evaluation Results & ROC Trade-Off Curve**
   - In tab **"5. Logs & Results"**, click **"Evaluation & ROC Chart"**.
   - Present the interactive Recharts ROC curve showing OpenJev System One (AUC 0.994), Microsoft-Decision-1 (AUC 0.991), and Baseline (AUC 0.892).
   - Point out the marked star at operating threshold ($\text{FPR}=1.2\%$, $\text{TPR}=99.5\%$) and benchmark table (sub-millisecond latency, \$0.15/1k calls).
