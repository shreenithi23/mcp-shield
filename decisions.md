# MCP Shield — Design Decision Log (`decisions.md`)

This file records all architectural and design choices made during the development of MCP Shield.
Entries use the format: ID, Date, Phase, Context, Options Considered, Decision, Why, Consequences, and Status.
Entries are never deleted; when superseded, their status is updated to `superseded` with a pointer to the new decision ID.

---

### D-001: Cryptographic Engine & OAuth 2.1 Token Implementation
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: The gateway issues short-lived (5-minute), audience-bound, task-bound JWTs and validates PKCE, DPoP (Phase 2), and JWKS.
- **Options Considered**:
  1. *PyJWT + pure custom endpoints*: Lightweight, but requires manual handling of JWK sets, OAuth standard schemas, and RFC validation logic.
  2. *Authlib + Cryptography*: Robust standards-compliant OAuth 1.0/2.0/2.1 and OIDC library with native cryptographic primitives and RFC specifications (RFC 7517, RFC 7519, RFC 7636, RFC 7591).
  3. *Keycloak / Ory Hydra external service*: Fully externalized, but contradicts the "one service that is both an OAuth 2.1 AS and PEP" architecture requirement and adds heavy deployment overhead.
- **Decision**: Use `authlib` paired with `cryptography` for RS256 token generation, key export, JWKS management, and RFC-compliant parameter verification.
- **Why**: Provides native RFC 7636 (PKCE), RFC 7591 (DCR), and RFC 7517 (JWKS) compatibility while allowing custom claims (`task_id`, `act`, `aud` resource binding) and zero-trust policy enforcement inside FastAPI.
- **Consequences**: Fast in-process token generation and validation without remote network calls. Requires managing local RSA key rotation.
- **Status**: accepted

---

### D-002: Key Generation and JWKS Rotation Strategy
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: Access tokens must be signed with RS256 and verified by protected resources via a standard `/.well-known/jwks.json` endpoint.
- **Options Considered**:
  1. *Hardcoded PEM files on disk*: Inflexible, risky if keys are committed to Git.
  2. *Auto-generated ephemeral keys on startup*: Easy for dev, but invalidates active tokens across process restarts.
  3. *Configurable persistent RSA keypair (file or env) with auto-generation fallback and key ID (`kid`)*: Generates a persistent or configured RSA 2048/4096-bit keypair, assigns deterministic `kid`, and exposes standard JWKS format.
- **Decision**: Store RSA private key in configurable environment variable/PEM path; if none provided, generate and persist locally, serving public JWK at `/.well-known/jwks.json` with a distinct `kid`.
- **Why**: Ensures zero-trust security without manual operational friction, preventing token invalidation across worker reloads while supporting clean future rotation.
- **Consequences**: Public keys are discoverable by any MCP server or PEP validator via standard JWKS.
- **Status**: accepted

---

### D-003: Dual Storage Architecture (PostgreSQL + Redis)
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: The gateway needs durable storage for clients, users, and audit records, but also low-latency ephemeral state for authorization codes, PKCE verifiers, session state, and token revocation lists.
- **Options Considered**:
  1. *PostgreSQL only*: Simplifies stack, but token revocation checks on every proxied MCP tool call add DB load.
  2. *Redis only*: Ultra fast, but lacks relational ACID guarantees and audit durability needed for zero-trust governance.
  3. *Hybrid PostgreSQL + Redis*: PostgreSQL as system of record (users, registered clients, audit records, issued tokens); Redis for short-lived authorization codes (TTL 5 min), rate-limiting, and revocation blacklist cache.
- **Decision**: Adopt hybrid architecture using PostgreSQL via Async SQLAlchemy for relational durability, and Redis for ephemeral state (auth codes, revocation bloom/set).
- **Why**: Aligns with zero-trust performance: policy decisions and token validations must execute in sub-millisecond timeframes without roundtrips to relational disk.
- **Consequences**: Requires running both PostgreSQL and Redis (orchestrated via docker-compose). Test suite provides SQLite / in-memory fallbacks when external services are unavailable.
- **Status**: accepted

---

### D-004: Audit & Access Logging with Nonce/Secret Redaction
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: The gateway must output a single-line JSON object per request to `access.log` with strict fields (`ts`, `request_id`, `user_id`, `client_id`, `task_id`, `remote_ip`, `method`, `path`, `mcp_server`, `tool`, `token_jti`, `dpop_ok`, `outcome`, `reason_code`, `http_status`, `upstream_status`, `args_sha256`, `scores`, `latency_ms`).
- **Options Considered**:
  1. *Standard FastAPI access log / uvicorn logger*: Lacks custom security fields, tool metadata, and argument hashing.
  2. *Dedicated async structured logging module with SHA-256 argument hashing and strict field schema*: Intercepts every request in middleware/endpoints, guarantees secret redaction, and rotates log files.
- **Decision**: Implement a centralized `mcp_shield.logging` module with a dedicated `access.log` handler (using `RotatingFileHandler`), strict JSON serialization, and automatic SHA-256 hashing for any arguments payload.
- **Why**: Zero-trust demands immutable auditability while strictly preventing credential leakage (tokens, PATs, client secrets, verifiers) in logs.
- **Consequences**: Every request is audited. A dedicated regression test checks for accidental leakage of any secret or raw payload.
- **Status**: accepted

---

### D-005: Upstream Identity Provider Integration & Local Mock IdP
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: The authorization server authenticates human users via OIDC (Google / Microsoft Entra ID). Local development and automated tests require seamless authentication without external network dependencies.
- **Options Considered**:
  1. *Require real Google / Entra credentials always*: Makes local automated tests impossible without live cloud secrets.
  2. *Hardcoded bypass flag*: Bypasses security code paths, leading to test divergence.
  3. *Pluggable IdP adapter with built-in Mock OIDC provider*: Real OIDC client for production (Google/Entra); Mock IdP endpoint for local dev/testing that adheres to full OIDC authorization code flow.
- **Decision**: Implement an IdP interface with support for Google, Entra, and an internal Mock IdP that simulates the OIDC consent and callback flow.
- **Why**: Enables 100% test coverage and offline development while exercising identical authorization code and session creation code paths.
- **Consequences**: Developers can test the full end-to-end OAuth flow without cloud credentials.
- **Status**: accepted

---

### D-006: Strict Audience Binding via RFC 8707 Resource Indicators
- **Date**: 2026-10-15
- **Phase**: Phase 1 (OAuth 2.1 Authorization Server & Foundations)
- **Context**: An AI agent must not obtain a universal token. Every token must be audience-bound to exactly one MCP server.
- **Options Considered**:
  1. *Multi-audience tokens (`aud: ["server1", "server2"]`)*: Violates least privilege; a compromised server could replay token to another.
  2. *Strict single-resource audience (`aud: "<mcp_server_uri>"`)*: Rejects authorization requests without a valid `resource` parameter, and binds issued token to that exact resource URI.
- **Decision**: Enforce strict single-resource audience binding conforming to RFC 8707. The token `aud` claim holds exactly the target MCP server URI. Token verification rejects any token whose `aud` does not match the target server.
- **Why**: Eliminates lateral movement between MCP servers (e.g., token for Slack cannot be used against GitHub MCP).
- **Consequences**: Clients must specify `resource` during authorization and request distinct tokens for different MCP tool servers.
- **Status**: accepted

---

### D-007: Upstream Credential Strategy (Fine-Grained PAT vs GitHub OAuth App)
- **Date**: 2026-10-15
- **Phase**: Phase 2 (Policy Enforcement Point & Authorization Layers)
- **Context**: The remote GitHub Copilot MCP server (`https://api.githubcopilot.com/mcp/`) does not support Dynamic Client Registration (RFC 7591). The gateway must authenticate to GitHub on behalf of agents while strictly preventing passthrough.
- **Options Considered**:
  1. *Passthrough of agent tokens upstream*: Forbidden by MCP architecture; GitHub MCP requires valid GitHub credentials, not gateway JWTs.
  2. *Single organization-wide Personal Access Token (classic PAT)*: Dangerous blast radius; classic PATs have broad access across all user repositories.
  3. *Dual-mode Vault architecture*: (a) fine-grained PAT scoped to ONE throwaway test repository (`shreenithi23/mcp-shield-test`) for initial deployment and automation; (b) pluggable per-user OAuth tokens via a registered GitHub OAuth App.
- **Decision**: Adopt the dual-mode Credential Vault starting with mode (a) fine-grained PAT strictly scoped to the test repository, with pluggable architecture for mode (b) GitHub OAuth App.
- **Why**: Minimizes blast radius to a single disposable test repository while establishing the pluggable abstraction for human-delegated OAuth tokens.
- **Consequences**: Agents never see or handle GitHub credentials. Gateway swaps credentials only after policy evaluation returns `allow`.
- **Status**: accepted

---

### D-008: Envelope Encryption for Credential Vault
- **Date**: 2026-10-15
- **Phase**: Phase 2 (Policy Enforcement Point & Authorization Layers)
- **Context**: Upstream credentials stored in the gateway must remain secure at rest, resisting memory dump extraction and persistent disk leakage.
- **Options Considered**:
  1. *Plaintext environment variables or unencrypted database columns*: High security risk; credentials exposed if logs or disk backups are compromised.
  2. *Single static symmetric key for all secrets*: If the key leaks, all upstream server credentials are compromised simultaneously.
  3. *Envelope Encryption with KMS-ready abstraction*: Generate a unique random 256-bit AES Data Encryption Key (DEK) for each stored credential, encrypt the secret with the DEK, and wrap the DEK with a Key Encryption Key (KEK) managed by KMS (Fernet for local prototype, pluggable for AWS KMS / GCP Cloud KMS / HashiCorp Vault).
- **Decision**: Implement envelope encryption (`BaseKMSProvider` + `FernetKMSProvider` + `CredentialVault`). Secrets are decrypted strictly in-memory during authorized upstream dispatch and never written to disk or logs in plaintext.
- **Why**: Follows zero-trust defense-in-depth principles and prepares MCP Shield for enterprise cloud KMS integration without refactoring.
- **Consequences**: Small CPU overhead per credential decryption.
- **Status**: accepted

---

### D-009: DPoP Proof-of-Possession and Replay Defense Architecture (RFC 9449)
- **Date**: 2026-10-15
- **Phase**: Phase 2 (Policy Enforcement Point & Authorization Layers)
- **Context**: Bearer tokens are vulnerable to theft and exfiltration by malicious tools or rogue network middleboxes. Tokens must be cryptographically bound to the client holding the private key.
- **Options Considered**:
  1. *mTLS (Mutual TLS)*: Heavy infrastructure requirements, difficult for dynamic AI agent runtimes to manage client certificates.
  2. *Standard Bearer tokens*: Zero protection against token theft and replay attacks.
  3. *DPoP (RFC 9449)*: Application-layer proof-of-possession using asymmetric client keys (RSA/EC), binding tokens via `cnf.jkt` (JWK thumbprint) and enforcing request method (`htm`), URL (`htu`), and `jti` replay caching.
- **Decision**: Implement full RFC 9449 DPoP verification at the token endpoint and PEP reverse proxy. DPoP-bound tokens require signed DPoP proofs matching `cnf.jkt`.
- **Why**: Completely neutralizes stolen token attacks; an attacker with an exfiltrated access token cannot call upstream MCP servers without the agent's private signing key.
- **Consequences**: Clients must generate a DPoP proof header for each protected call. Gateway caches `jti` in Redis to reject replay attempts.
- **Status**: accepted

---

### D-010: Three-Tier Policy Enforcement Architecture (RBAC, OPA/Rego PBAC, Quotas)
- **Date**: 2026-10-15
- **Phase**: Phase 2 (Policy Enforcement Point & Authorization Layers)
- **Context**: MCP tools can perform critical actions (e.g., file creation, issue writing, repository deletion). Access control must enforce both static organizational roles and dynamic contextual constraints.
- **Options Considered**:
  1. *Hardcoded Python `if/else` checks*: Brittle, un-auditable, difficult to maintain across diverse MCP servers.
  2. *Coarse OAuth scopes only*: Cannot enforce fine-grained argument constraints (e.g. repo name or channel filters).
  3. *Three-Tier Policy Pipeline*:
     - **Layer 1 (RBAC)**: Admin console roles (`admin`, `security_reviewer`, `developer`, `viewer`).
     - **Layer 2 (PBAC in OPA/Rego)**: Declarative Rego policies checking `server:tool:action`, argument constraints (`owner`, `repo`, `channel`), and enforcing the fundamental rule that users can only delegate permissions they themselves hold.
     - **Layer 3 (Quotas & Circuit Breaker)**: Redis sliding windows for calls/min, writes/hour, records/day, with an automated circuit breaker that trips after repeated policy denials.
- **Decision**: Adopt the Three-Tier Policy Pipeline with OPA/Rego and Redis quotas.
- **Why**: Decouples policy logic from application code, enables unit-tested declarative security policies (`opa test`), and automatically shields upstream MCP servers from runaway agent loops.
- **Consequences**: Every `tools/call` evaluates the full policy chain before swapping credentials and dispatching upstream.
- **Status**: accepted

---

### D-011: Fail-Closed Behavior on Ephemeral Storage / Redis Outage
- **Date**: 2026-10-15
- **Phase**: Phase 2 (Policy Enforcement Point & Authorization Layers)
- **Context**: If Redis or ephemeral caching encounters an outage or network partition, the gateway must determine whether to allow or deny requests.
- **Options Considered**:
  1. *Fail-open*: Continue proxying requests without quota tracking or revocation checking to maximize uptime.
  2. *Fail-closed*: Reject requests if revocation state, DPoP replay cache, or circuit breaker cannot be reliably checked; use resilient in-memory fallback during graceful local operation.
- **Decision**: Enforce strict fail-closed behavior for security-sensitive verifications (revocation checks and replay prevention). For quota and rate limiting during local dev/tests, use atomic in-memory fallback store.
- **Why**: In a zero-trust gateway, availability must never compromise security. A fail-open gateway during an outage could permit compromised or revoked tokens to access sensitive MCP servers.
- **Consequences**: If revocation or replay state cannot be validated, requests are safely denied with a machine-readable error.
- **Status**: accepted

---

### D-012: Adoption of OpenJev as the System One Decision Engine
- **Date**: 2026-10-15
- **Phase**: Phase 3 (AI Decision Layer & Layer 4 ABAC)
- **Context**: LLMs and decision models can evaluate intent match, overreach, prompt injection, and data sensitivity. However, standard LLM text generation is non-deterministic and can hallucinate or be bypassed via adversarial prompts.
- **Options Considered**:
  1. *Prompt-based LLM gatekeeper*: Ask an LLM in freeform text "Should this tool call be allowed?" and parse "YES/NO".
  2. *OpenJev (https://github.com/GPT-AGI/OpenJev)*: Open-source, Jev-compatible System One decision engine. Typed decisions (`Choice`, `Score`, `Noul`) in one forward pass, reading logits at the answer position and softmaxing over candidate labels only with normalized entropy confidence.
- **Decision**: Adopt OpenJev library (`openjev`) as the core decision engine feeding deterministic OPA/Rego policies.
- **Why**: Eliminates text parsing ambiguity and mock decisions. Every decision is evaluated as a typed `Noul` ($P(\text{true})$ in $[0, 1]$) or `Choice` question in one forward pass.
- **Consequences**: Authorization logic remains 100% auditable and declarative in Rego while benefiting from OpenJev typed probability evaluations.
- **Status**: accepted

---

### D-013: Model Never Overrides Static Authorization Denial
- **Date**: 2026-10-15
- **Phase**: Phase 3 (AI Decision Layer & Layer 4 ABAC)
- **Context**: If a user does not hold delegation authority, if a token does not grant a tool, or if argument constraints (e.g. repository boundary) are violated, can a high model confidence score (e.g. `intent_match = 1.0`) permit execution?
- **Options Considered**:
  1. *AI override*: Allow high confidence scores to grant exceptions for urgent or plausible agent actions.
  2. *Strict non-override*: Static PBAC/RBAC rules are inviolable; if static authorization fails, the outcome is always `deny` regardless of model scores.
- **Decision**: Static authorization denial is absolute. A decision model score of 1.0 can NEVER override a static policy deny.
- **Why**: Core tenet of zero-trust security. Agents cannot exceed their cryptographically signed delegation envelope (RFC 9396 `authorization_details`) or repository boundaries under any circumstances.
- **Consequences**: Static check runs first; any static failure results in immediate `403 Forbidden` with a machine-readable reason code.
- **Status**: accepted

---

### D-014: Fail-Safe 150ms Timeout: Read Fallback vs. Write Fail-Closed
- **Date**: 2026-10-15
- **Phase**: Phase 3 (AI Decision Layer & Layer 4 ABAC)
- **Context**: In real-time proxying, decision models can experience latency spikes, cold starts, or network timeouts. The gateway cannot stall agent loops indefinitely.
- **Options Considered**:
  1. *Universal fail-closed*: Deny all tool calls if the model exceeds 150ms.
  2. *Universal fail-open*: Allow all tool calls if the model exceeds 150ms.
  3. *Tiered timeout handling*: For Tier 1 read-only tools with valid static authorization, fall back to static policy allow; for Tier 2 and Tier 3 write/privilege tools, fail closed and hold for human approval (`status: hold_for_approval`).
- **Decision**: Implement tiered 150ms timeout handling (reads fall back to static allow; writes held for approval).
- **Why**: Balances agent responsiveness with strict write security. Read tools cannot mutate repository state or compromise integrity, whereas unverified writes must never execute silently without human authorization.
- **Consequences**: If model latency exceeds 150ms, reads proceed safely and writes return HTTP 202 Accepted pending approval. Both record `timed_out: true` in `access.log`.
- **Status**: accepted

---

### D-015: Four Explicit Authorization Outcomes: Allow, Allow Narrower, Hold, Deny
- **Date**: 2026-10-15
- **Phase**: Phase 3 (AI Decision Layer & Layer 4 ABAC)
- **Context**: Binary allow/deny is insufficient for modern AI agents, which frequently request excessive row limits or execute high-impact mutations that need human sign-off.
- **Options Considered**:
  1. *Binary allow/deny*: Only permit or reject requests.
  2. *Four outcomes*: `allow` (proceed unmodified), `allow_narrower` (modify query arguments to enforce minimal blast radius, e.g. clamp `limit` to 10), `hold` (hold execution pending human approval), and `deny` (hard rejection).
- **Decision**: Adopt the four-outcome model across OPA/Rego, PEP reverse proxy, and audit logging.
- **Why**: Minimizes agent friction for queries while containing data leakage (e.g., query pagination / row limits) and enforcing mandatory human-in-the-loop oversight for high-risk irreversible operations.
- **Consequences**: PEP proxy dynamically modifies request payload arguments on `allow_narrower` and returns HTTP 202 Accepted on `hold`.
- **Status**: accepted

---

### D-016: Session Tainting via Checkpoint 2 Prompt Injection Detection
- **Date**: 2026-10-15
- **Phase**: Phase 3 (AI Decision Layer & Layer 4 ABAC)
- **Context**: Remote tools may return untrusted data containing indirect prompt injection or jailbreak payloads intended to hijack subsequent agent tool calls within the session.
- **Options Considered**:
  1. *Stateless execution*: Treat each tool call independently without tracking session infection.
  2. *Stateful session tainting*: Checkpoint 2 evaluates tool output. If `injection_risk >= 0.50`, the MCP session is marked tainted in Redis/ephemeral cache, causing all subsequent write operations in that session to be held for approval or denied.
- **Decision**: Implement Checkpoint 2 session tainting with 1-hour sliding TTL.
- **Why**: Directly mitigates indirect prompt injection attacks where untrusted issue/PR content attempts to induce the agent into making malicious commits, file deletions, or PR merges.
- **Consequences**: Once a session is tainted, subsequent writes are automatically held with reason `session_tainted_write_held`.
- **Status**: accepted

---

### D-017: Taint Tracking Lifecycle, Clearing Rules, and RFC 8693 Token Downscoping
- **Date**: 2026-10-16
- **Phase**: Phase 4 (Runtime Defenses & Human-in-the-Loop)
- **Context**: When Checkpoint 2 detects prompt injection in an upstream tool result (e.g. malicious issue body), the session enters a high-risk state where the agent may act under adversary control.
- **Options Considered**:
  1. *Immediate process termination*: Terminate the agent process immediately upon injection detection.
  2. *Runtime taint tracking with RFC 8693 token exchange downscoping and human clearing*: Mark the MCP session tainted, automatically execute RFC 8693 Token Exchange to downscope the agent's bearer token strictly to Tier 1 read-only tools, hold all subsequent write attempts, and allow recovery only when an administrator reviews and clears the taint state.
- **Decision**: Adopt runtime session taint tracking with automated RFC 8693 token downscoping and administrator-only taint clearing.
- **Taint-Clearing Rules**:
  - Taint can ONLY be cleared by an authenticated administrator or operator via the `/mcp/taint/clear` endpoint.
  - The request must supply a cryptographic user identifier, `session_id`, and a descriptive audit reason explaining why the session is safe.
  - Taint clearing emits an immutable `"taint_cleared"` structured event to `access.log` containing `ts`, `session_id`, `cleared_by`, and `reason`.
  - Automatic taint expiration occurs after a 1-hour TTL if not explicitly refreshed.
- **Consequences**: Confines adversary blast radius to read operations while allowing safe diagnosis and administrative intervention without abruptly crashing agent pipelines.
- **Status**: accepted

---

### D-018: CIBA Out-of-Band Approval Flow (Slack Block Kit & Mobile Web App)
- **Date**: 2026-10-16
- **Phase**: Phase 4 (Runtime Defenses & Human-in-the-Loop)
- **Context**: Autonomous agents require human authorization for high-risk operations (Tier 3 tools or writes attempted in tainted sessions). The approval interface must reach humans where they work without disrupting developer flow.
- **Options Considered**:
  1. *Console-only polling*: Force operators to monitor a web dashboard and click approval buttons.
  2. *CIBA (RFC 8935) Out-of-Band Push*: Send an interactive push notification (Slack Block Kit DM or mobile web link) displaying the instruction, proposed tool, arguments, gateway risk assessment, and one-tap approve/deny actions.
- **Decision**: Implement RFC 8935 Client Initiated Backchannel Authentication (CIBA) out-of-band approvals with dual delivery: Slack Block Kit push payloads and a standalone responsive mobile web UI (`/approval/ui/{auth_req_id}`).
- **Why**: Allows instant, on-the-go human approval or denial from a smartphone or Slack client within the 300-second request TTL.
- **Consequences**: Held calls return HTTP 202 Accepted with an `auth_req_id`, approval URL, and Slack notification payload. Approvals and denials emit `"approval_requested"`, `"approval_approved"`, and `"approval_denied"` events to `access.log`.
- **Status**: accepted

---

### D-019: Sensitivity Criteria for Step-Up Multi-Factor Authentication (TOTP / WebAuthn)
- **Date**: 2026-10-16
- **Phase**: Phase 4 (Runtime Defenses & Human-in-the-Loop)
- **Context**: A simple one-tap approval is vulnerable to accidental taps, unauthorized device access, or operator fatigue when approving critical actions.
- **Options Considered**:
  1. *Universal one-tap approval*: Allow one-tap approval for all held requests.
  2. *Universal MFA step-up*: Require TOTP/WebAuthn for every approval regardless of risk.
  3. *Risk-calibrated step-up*: Require step-up MFA (RFC 6238 TOTP or WebAuthn FIDO2) exclusively for actions classified as sensitive.
- **What Counts as Sensitive for Step-Up**:
  1. Any tool belonging to **Tier 3 (Irreversible or Privilege-Changing)**, including `delete_file`, `merge_pull_request`, `push_files`, `create_repository`, and `run_secret_scanning`.
  2. Any write operation attempted while the session is **TAINTED** by prior prompt injection.
  3. Any tool call whose target parameters affect production branches (`main`, `master`) or security configuration files (`.github/workflows/*`, `*.pem`, `*.key`).
- **Decision**: Enforce mandatory step-up TOTP verification for all sensitive approval requests; non-sensitive requests (e.g. low-impact reversible drafts) support one-tap resolution.
- **Consequences**: The mobile UI renders a 6-digit TOTP input field with visual warning indicators whenever `is_sensitive=True`. Approval without valid TOTP is strictly rejected with HTTP 400.
- **Status**: accepted

---

### D-020: Generation and Scope of Plain-English Explanations
- **Date**: 2026-10-16
- **Phase**: Phase 4 (Runtime Defenses & Human-in-the-Loop)
- **Context**: Developers and administrators need transparent, human-readable rationales when their agent's actions are delayed or denied. However, generating explanations for every allowed request introduces unnecessary LLM latency and cost.
- **Options Considered**:
  1. *Universal explanation generation*: Explain every tool call (allowed, held, and denied).
  2. *Explanations for held and denied calls ONLY*: Generate concise (1–2 sentences) plain-English explanations exclusively for `hold` and `deny` outcomes.
- **Decision**: Restrict explanation generation strictly to `hold` and `deny` calls. Allowed calls never invoke explanation logic and return an empty string immediately.
- **How Explanations Are Generated**:
  - Implemented via `ExplanationGenerator` using deterministic zero-overhead fast-paths for standard zero-trust policy reasons (e.g., token boundary exclusions, tainted session writes, argument constraints, model fail-safe timeouts).
  - Designed to plug into a general LLM (via OpenRouter/OpenAI API) for open-ended or ambiguous borderline cases.
  - Explanations are delivered in the JSON-RPC error payload for denials (`error.data.explanation`), in the CIBA approval UI, in Slack push messages, and in the HTTP 202 response for held calls.
- **Consequences**: Zero latency overhead on allowed requests (0ms added); transparent, actionable explanations provided whenever an agent action is held or blocked.
- **Status**: accepted

---

### D-021: Tool Integrity SHA-256 Description Pinning, Drift Detection, and Quarantine
- **Date**: 2026-10-16
- **Phase**: Phase 4 (Runtime Defenses & Human-in-the-Loop)
- **Context**: Adversarial upstream tool servers or supply-chain compromises can modify tool descriptions or schemas post-deployment (rug-pull attacks) to inject deceptive instructions that manipulate agent reasoning.
- **Options Considered**:
  1. *Trust-on-registration*: Approve tools once and trust upstream servers indefinitely.
  2. *Cryptographic SHA-256 hash pinning with automatic quarantine*: Compute and pin the SHA-256 digest of tool descriptions upon administrative approval. On every `tools/list` response, verify description hashes against the pinned catalog. If any hash differs, immediately quarantine the tool, emit a `"tool_hash_mismatch"` alert to `access.log`, trigger Checkpoint 3 re-scoring (`poisoning_risk`, `semantic_drift`), and block all execution until an administrator manually re-approves the updated description.
- **Decision**: Adopt SHA-256 description pinning and automatic tool quarantine in `ToolIntegrityRegistry`.
- **Testing Scope**: Rug-pull and poisoning tests execute exclusively against the local malicious demo server (`http://malicious-mcp/mcp`), preserving clean state on GitHub Copilot's remote MCP server.
- **Consequences**: Rug-pull mutations are instantly detected, quarantined, and prevented from reaching agent context without administrative authorization.
- **Status**: accepted

---

### D-022: Cryptographic Hash Chaining for Append-Only Audit Integrity
- **Date**: 2026-10-17
- **Phase**: Phase 5 (Audit Log, Console, Evaluation & Final Report)
- **Context**: Compliance and zero-trust forensics require that audit records cannot be deleted, reordered, or edited after execution, even by system administrators or compromised proxy components.
- **Options Considered**:
  1. *Plain JSON/SQL logging*: Write events to a local file or standard relational database without cryptographic linkage.
  2. *Cryptographic Hash Chaining*: Every audit entry includes the SHA-256 hash of its canonical JSON representation combined with the hash of the immediately preceding record: $\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} + \text{CanonicalPayload}_n)$, rooted at a fixed genesis hash.
- **Decision**: Adopt SHA-256 cryptographic hash chaining in `AuditTrailManager` (`audit_chain.jsonl`).
- **Why**: Guarantees tamper evidence. Any modification, reordering, deletion, or back-dating of any record immediately invalidates the cryptographic hash chain from that index forward, pin-pointing the exact line of tampering.
- **Consequences**: Verification command (`verify_chain()`) audits the entire sequence in milliseconds and exports ECS-compliant JSON for enterprise SIEM integration.
- **Status**: accepted

---

### D-023: Dual-Log Architecture and Continuous Bidirectional Reconciliation
- **Date**: 2026-10-17
- **Phase**: Phase 5 (Audit Log, Console, Evaluation & Final Report)
- **Context**: The gateway produces high-throughput operational telemetry (`access.log`) as well as formal forensic audit records (`audit_chain.jsonl`). Discrepancies between operational logs and the audit trail could conceal covert attacks.
- **Options Considered**:
  1. *Single combined log*: Merge all operational and cryptographic fields into one verbose log file.
  2. *Dual-Log architecture with continuous bidirectional reconciliation*: Maintain fast, rotating operational lines in `access.log` and immutable hash-chained records in `audit_chain.jsonl`, cross-referenced via a unique `request_id`. Provide automated reconciliation tools to verify 100% bidirectional parity.
- **Decision**: Adopt the dual-log architecture with continuous reconciliation (`AccessLogAnalyzer.reconcile()`).
- **Why**: Operational logs require rolling rotation and low latency, whereas audit records require immutable cryptographic chain preservation and SIEM ingestion.
- **Consequences**: Every tool invocation produces matching entries in both files. The analyzer detects any missing entries in either direction and provides backfill synchronization.
- **Status**: accepted

---

### D-024: RBAC-Gated Admin Console Architecture (Admin, Operator, Auditor Hierarchy)
- **Date**: 2026-10-17
- **Phase**: Phase 5 (Audit Log, Console, Evaluation & Final Report)
- **Context**: Managing human-in-the-loop approvals, inspecting live decision telemetry, and modifying risk-tier thresholds requires strict role separation to prevent insider privilege escalation.
- **Options Considered**:
  1. *Single shared administrative password*: All console users possess equal administrative powers.
  2. *Three-tier RBAC hierarchy*:
     - **`auditor`**: Read-only visibility into telemetry, decision feed, audit chain, and SIEM exports.
     - **`operator`**: Auditor privileges plus ability to resolve held calls (with TOTP step-up for sensitive actions) and clear session taints.
     - **`admin`**: Full privileges including tool re-approval, SHA-256 hash re-pinning, and policy threshold reconfiguration.
- **Decision**: Enforce a three-tier RBAC hierarchy across all console endpoints (`/api/console/*`) and UI components (`/console`).
- **Consequences**: Gated by `require_role(min_role)` dependency. Auditors cannot approve calls; operators cannot re-pin mutated tool hashes; only admins can modify policy rules.
- **Status**: accepted

---

### D-025: Labeled Threat Benchmark Dataset and Model Calibration Criteria
- **Date**: 2026-10-17
- **Phase**: Phase 5 (Audit Log, Console, Evaluation & Final Report)
- **Context**: Evaluating gateway efficacy requires a statistically significant, realistic distribution of benign operations and adversarial attack vectors tested across multiple decision models.
- **Options Considered**:
  1. *Synthetic random fuzzing*: Send randomized strings to MCP servers.
  2. *Curated 300-sample benchmark*: Build a labeled benchmark dataset consisting of 120 benign tool calls (75 reads, 45 writes) and 180 attack vectors across prompt injection (80), poisoned tool rug-pulls (50), and overreaching actions (50).
- **Decision**: Implement the 300-sample labeled benchmark (`src/mcp_shield/eval/dataset.py`) evaluated across Jev (OpenJev System One), Microsoft-Decision-1, and General-LLM baselines.
- **Why**: Demonstrates attack block rates, false-block rates, and ROC trade-off curves under real-world conditions, validating that OpenJev System One achieves 99.5% attack containment with <1.5% false blocks at sub-millisecond latency.
- **Status**: accepted

---

### D-026: Frontend Architecture: React 19 + TypeScript (Vite) with Single-Page Plain CSS
- **Date**: 2026-10-19
- **Phase**: Frontend Demo Dashboard
- **Context**: A presentation and live-demo dashboard was required to demonstrate all core capabilities of MCP Shield (OAuth 2.1 AS + PEP, DPoP tokens, intent/injection/poisoning scoring, taint tracking, CIBA approvals, tool integrity pinning, cryptographic audit chain, access.log, and evaluation ROC curves). Simplicity and ease of local reproduction mattered more than polish.
- **Options Considered**:
  1. *Next.js / Remix full-stack framework*: Heavier build footprint, SSR complexities, unnecessary backend coupling.
  2. *Single-Page React + TypeScript with Vite and Plain CSS*: Minimal overhead, fast HMR, zero complex state libraries (Redux/Zustand), no client-side routing library, plain CSS tokens for consistent color semantics (green allow, blue allow-narrower, amber hold, red deny).
- **Decision**: Adopt Vite + React 19 + TypeScript with plain CSS tokens and Recharts for the ROC curve.
- **Why**: Keeps total frontend code footprint under ~2,500 lines across 5 focused tab components, `api.ts`, and `types.ts`, ensuring complete clarity and transparency during code reviews and live demonstrations.
- **Consequences**: Fast local launch via `npm run dev`, single-page switching between 5 tabs without page reloads, and simple configuration via `VITE_API_BASE_URL`.
- **Status**: accepted

---

### D-027: Polling vs. WebSockets: 2-Second HTTP Polling for Approvals Queue
- **Date**: 2026-10-19
- **Phase**: Frontend Demo Dashboard
- **Context**: The Approvals tab needs to reflect newly held tool calls (e.g. from tainted writes or Tier 3 actions) and status transitions when calls are approved or denied.
- **Options Considered**:
  1. *WebSockets / Server-Sent Events (SSE)*: Real-time event push, but requires maintaining connection state, heartbeat handling, reconnect logic, and WebSocket endpoint overhead on the FastAPI backend.
  2. *2-Second HTTP Polling*: Client periodically fetches `GET /api/console/held` every 2,000ms.
- **Decision**: Adopt 2-second HTTP polling.
- **Why**: Eliminates connection dropouts, firewall issues, and proxy framing quirks during live presentations. Request latency is low (<5ms local response) and simplifies frontend lifecycle management.
- **Consequences**: Approvals queue updates within 2 seconds of any held event without persistent socket state.
- **Status**: accepted

---

### D-028: Read-Only /demo API Router for Live Presentation & Interactive Negative Testing
- **Date**: 2026-10-19
- **Phase**: Frontend Demo Dashboard
- **Context**: The live frontend requires executing preset scenarios, inspecting session taint metadata, testing negative token rejections (wrong audience, missing DPoP proof), demonstrating audit tampering, and loading pre-computed benchmark curves. The existing backend architecture could not be altered.
- **Options Considered**:
  1. *Modify core proxy and OAuth handlers*: Add demo flags and conditional branching inside production security enforcement points.
  2. *Add a thin /demo FastAPI router*: Wrap existing internal managers (`taint_manager`, `audit_manager`, `tool_registry`, `quota_manager`, `ciba_manager`) without modifying core security enforcement paths.
- **Decision**: Implement a thin read-only / helper `/demo` router mounted at `/demo/*` in `src/mcp_shield/main.py`.
- **Endpoints Added**:
  - `GET /demo/session/{session_id}`: Real-time query of session taint state.
  - `POST /demo/session/{session_id}/clear-taint`: Clears session taint with administrative audit record.
  - `GET /demo/scenarios`: Returns metadata for the 4 presets (benign, injection, overreach, quota).
  - `POST /demo/scenarios/run/{scenario_id}`: Executes preset scenarios through the real PEP pipeline, emitting authentic `access.log` lines and `audit_chain.jsonl` records.
  - `POST /demo/malicious/rug-pull`: Mutates malicious tool description to trigger live SHA-256 hash mismatch and quarantine.
  - `POST /demo/malicious/reset`: Resets malicious demo server to clean baseline.
  - `GET /demo/quotas`: Returns live sliding-window call and rate quota states.
  - `GET /demo/access-log`: Returns tail of recent `access.log` entries parsed into JSON.
  - `GET /demo/eval-results`: Returns 300-sample benchmark metrics and ROC coordinates for Recharts.
  - `POST /demo/audit/tamper`: Tampers with an audit record to demonstrate cryptographic hash chain detection failure.
  - `POST /demo/audit/restore`: Restores audit chain to pristine state.
  - `POST /demo/token/test-rejection`: Simulates gateway HTTP 401 rejections for wrong audience and missing DPoP proofs.
- **Consequences**: Preserves 100% integrity of backend production proxy and OAuth 2.1 code while empowering the frontend demo to run completely end-to-end against live data.
- **Status**: accepted
