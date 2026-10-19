import type {
  AgentClient,
  AuditRecord,
  DecodedToken,
  EvalResults,
  HeldCall,
  QuotaData,
  RegisteredTool,
  ScenarioPreset,
  SessionStatus,
  TimelineStep,
  UserSession,
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/**
 * Safely decodes a JWT token without exposing signature or secret material.
 * Only returns the standard JSON claims object.
 */
export function decodeJwtClaims(rawJwt: string): DecodedToken | null {
  try {
    const parts = rawJwt.split(".");
    if (parts.length < 2) return null;
    const payloadBase64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const jsonStr = decodeURIComponent(
      atob(payloadBase64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    const parsed = JSON.parse(jsonStr);
    return {
      ...parsed,
      raw_token: rawJwt,
    };
  } catch (e) {
    console.error("Failed to decode JWT claims:", e);
    return null;
  }
}

// -------------------------------------------------------------
// Authentication & Registration
// -------------------------------------------------------------

export async function loginUser(
  username: string = "alice_dev",
  role: string = "admin"
): Promise<{ user: UserSession; token: string; decoded: DecodedToken | null }> {
  const resp = await fetch(`${API_BASE}/demo/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      role,
      client_id: "agent_copilot_assistant",
    }),
  });

  if (!resp.ok) {
    throw new Error(`Login failed with HTTP ${resp.status}`);
  }

  const data = await resp.json();
  const token = data.access_token;
  const decoded = decodeJwtClaims(token);

  return {
    user: {
      sub: decoded?.sub || username,
      name: username === "alice_dev" ? "Alice (Platform Engineer)" : username,
      role: role,
    },
    token,
    decoded,
  };
}

export async function registerAgent(
  clientName: string = "GitHub Copilot Bug Assistant"
): Promise<AgentClient> {
  const resp = await fetch(`${API_BASE}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: clientName,
      redirect_uris: ["https://client.example.com/callback"],
      grant_types: ["authorization_code", "client_credentials"],
      response_types: ["code"],
      scope: "mcp:tools repo",
    }),
  });

  if (!resp.ok) {
    throw new Error(`DCR registration failed with HTTP ${resp.status}`);
  }

  return await resp.json();
}

// -------------------------------------------------------------
// Session & Taint Tracking
// -------------------------------------------------------------

export async function getSessionStatus(sessionId: string): Promise<SessionStatus> {
  const resp = await fetch(`${API_BASE}/demo/session/${sessionId}`);
  if (!resp.ok) {
    return { session_id: sessionId, tainted: false };
  }
  return await resp.json();
}

export async function clearSessionTaint(sessionId: string): Promise<boolean> {
  const resp = await fetch(`${API_BASE}/demo/session/${sessionId}/clear-taint`, {
    method: "POST",
  });
  if (!resp.ok) return false;
  const data = await resp.json();
  return data.cleared === true || data.tainted === false;
}

// -------------------------------------------------------------
// Scenarios & Live Run
// -------------------------------------------------------------

export async function fetchScenarios(): Promise<ScenarioPreset[]> {
  const resp = await fetch(`${API_BASE}/demo/scenarios`);
  if (!resp.ok) throw new Error("Could not load preset scenarios");
  return await resp.json();
}

export async function runDemoScenario(
  scenarioId: string,
  instruction: string,
  sessionId: string,
  clientId?: string
): Promise<{
  scenario_id: string;
  session_id: string;
  is_tainted: boolean;
  steps: TimelineStep[];
}> {
  const resp = await fetch(`${API_BASE}/demo/scenarios/run/${scenarioId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      instruction,
      session_id: sessionId,
      client_id: clientId || "agent_copilot_assistant",
      user_id: "usr_alice",
    }),
  });

  if (!resp.ok) {
    throw new Error(`Scenario run failed with HTTP ${resp.status}`);
  }

  return await resp.json();
}

// -------------------------------------------------------------
// Tokens Tab Operations
// -------------------------------------------------------------

export async function introspectToken(token: string): Promise<any> {
  const form = new URLSearchParams();
  form.append("token", token);
  const resp = await fetch(`${API_BASE}/oauth/introspect`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  return await resp.json();
}

export async function revokeToken(token: string): Promise<any> {
  const form = new URLSearchParams();
  form.append("token", token);
  const resp = await fetch(`${API_BASE}/oauth/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  return { status: resp.status, message: "Token revoked successfully" };
}

export async function testTokenRejection(type: "wrong_server" | "missing_dpop"): Promise<any> {
  const resp = await fetch(`${API_BASE}/demo/token/test-rejection?test_type=${type}`, {
    method: "POST",
  });
  return await resp.json();
}

// -------------------------------------------------------------
// Approvals Tab (Held Calls & CIBA)
// -------------------------------------------------------------

export async function fetchHeldQueue(): Promise<HeldCall[]> {
  const resp = await fetch(`${API_BASE}/api/console/held`, {
    headers: { "x-user-role": "operator" },
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.items || [];
}

export async function resolveHeldCall(
  authReqId: string,
  action: "approve" | "deny",
  totpCode?: string
): Promise<any> {
  const form = new URLSearchParams();
  form.append("action", action);
  if (totpCode) {
    form.append("totp_code", totpCode);
  }

  const resp = await fetch(`${API_BASE}/api/console/held/${authReqId}/action`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "x-user-role": "operator",
    },
    body: form.toString(),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: "Resolution failed" }));
    throw new Error(err.detail || `Action failed with ${resp.status}`);
  }

  return await resp.json();
}

// -------------------------------------------------------------
// Tools & Policy Tab
// -------------------------------------------------------------

export async function fetchTools(): Promise<RegisteredTool[]> {
  const resp = await fetch(`${API_BASE}/api/console/tools`, {
    headers: { "x-user-role": "auditor" },
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.tools || [];
}

export async function approveTool(
  toolName: string,
  serverUri: string,
  description: string
): Promise<any> {
  const form = new URLSearchParams();
  form.append("tool_name", toolName);
  form.append("server_uri", serverUri);
  form.append("description", description);

  const resp = await fetch(`${API_BASE}/api/console/tools/approve`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "x-user-role": "admin",
    },
    body: form.toString(),
  });

  return await resp.json();
}

export async function simulateRugPull(): Promise<any> {
  const resp = await fetch(`${API_BASE}/demo/malicious/rug-pull`, {
    method: "POST",
  });
  return await resp.json();
}

export async function resetMaliciousServer(): Promise<any> {
  const resp = await fetch(`${API_BASE}/demo/malicious/reset`, {
    method: "POST",
  });
  return await resp.json();
}

export async function fetchPolicies(): Promise<any> {
  const resp = await fetch(`${API_BASE}/api/console/policies`, {
    headers: { "x-user-role": "auditor" },
  });
  if (!resp.ok) return null;
  return await resp.json();
}

export async function fetchQuotas(clientId: string): Promise<QuotaData | null> {
  const resp = await fetch(`${API_BASE}/demo/quotas?client_id=${clientId}`);
  if (!resp.ok) return null;
  return await resp.json();
}

// -------------------------------------------------------------
// Logs & Results Tab
// -------------------------------------------------------------

export async function fetchAuditStatus(): Promise<any> {
  const resp = await fetch(`${API_BASE}/api/console/audit`, {
    headers: { "x-user-role": "auditor" },
  });
  if (!resp.ok) return null;
  return await resp.json();
}

export async function fetchAuditFeed(limit: number = 30): Promise<AuditRecord[]> {
  const resp = await fetch(`${API_BASE}/api/console/feed?limit=${limit}`, {
    headers: { "x-user-role": "auditor" },
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.items || [];
}

export async function tamperAuditRecord(): Promise<any> {
  const resp = await fetch(`${API_BASE}/demo/audit/tamper`, {
    method: "POST",
  });
  return await resp.json();
}

export async function restoreAuditChain(): Promise<any> {
  const resp = await fetch(`${API_BASE}/demo/audit/restore`, {
    method: "POST",
  });
  return await resp.json();
}

export async function fetchAccessLog(
  outcome?: string,
  tool?: string,
  limit: number = 200
): Promise<any[]> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  if (outcome) params.append("outcome", outcome);
  if (tool) params.append("tool", tool);

  const resp = await fetch(`${API_BASE}/demo/access-log?${params.toString()}`);
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.items || [];
}

export async function fetchEvalResults(): Promise<EvalResults | null> {
  const resp = await fetch(`${API_BASE}/demo/eval-results`);
  if (!resp.ok) return null;
  return await resp.json();
}
