"""Interactive React + TypeScript Single Page Admin Console for MCP Shield."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

ui_router = APIRouter(tags=["Admin Console UI"])


@ui_router.get("/console", response_class=HTMLResponse, summary="MCP Shield Admin Console")
async def render_admin_console():
    """Renders the executive React + TypeScript Single-Page Application."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MCP Shield — Zero-Trust Admin Console</title>
  <!-- React 18 & Babel for TypeScript/JSX execution -->
  <script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <!-- Google Fonts: Inter -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  
  <style>
    :root {
      --bg-primary: #090d16;
      --bg-surface: #111827;
      --bg-card: rgba(17, 24, 39, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-hover: rgba(59, 130, 246, 0.4);
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --accent-purple: #8b5cf6;
      --text-primary: #f9fafb;
      --text-secondary: #9ca3af;
      --text-muted: #6b7280;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-primary);
      color: var(--text-primary);
      font-family: 'Inter', sans-serif;
      overflow-x: hidden;
      min-height: 100vh;
      background-image: 
        radial-gradient(circle at 15% 10%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(139, 92, 246, 0.08) 0%, transparent 40%);
    }
    code, pre { font-family: 'JetBrains Mono', monospace; }
    .glass-card {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      transition: all 0.2s ease-in-out;
    }
    .glass-card:hover {
      border-color: var(--border-hover);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.02em;
      text-transform: uppercase;
    }
    .badge-allow { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-hold { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-deny { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge-quarantined { background: rgba(239, 68, 68, 0.25); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.5); }
    .badge-approved { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    
    .btn {
      padding: 7px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-primary { background: #3b82f6; color: white; }
    .btn-primary:hover { background: #2563eb; }
    .btn-success { background: #10b981; color: white; }
    .btn-success:hover { background: #059669; }
    .btn-danger { background: #ef4444; color: white; }
    .btn-danger:hover { background: #dc2626; }
    .btn-ghost { background: rgba(255,255,255,0.05); color: var(--text-secondary); border: 1px solid var(--border-color); }
    .btn-ghost:hover { background: rgba(255,255,255,0.1); color: white; }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-primary); }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.25); }
  </style>
</head>
<body>
  <div id="root"></div>

  <script type="text/babel">
    const { useState, useEffect } = React;

    function App() {
      const [role, setRole] = useState("admin"); // admin, operator, auditor
      const [activeTab, setActiveTab] = useState("overview"); // overview, feed, held, tools, policies, audit
      const [stats, setStats] = useState(null);
      const [feed, setFeed] = useState([]);
      const [heldItems, setHeldItems] = useState([]);
      const [tools, setTools] = useState([]);
      const [policies, setPolicies] = useState(null);
      const [auditStatus, setAuditStatus] = useState(null);
      const [totpModal, setTotpModal] = useState(null); // { authReqId, action, tool }
      const [totpCode, setTotpCode] = useState("");
      const [toast, setToast] = useState(null);

      const showToast = (msg, type = "success") => {
        setToast({ msg, type });
        setTimeout(() => setToast(null), 3500);
      };

      const fetchAllData = async () => {
        const headers = { "x-user-role": role };
        try {
          const sRes = await fetch("/api/console/stats", { headers });
          if (sRes.ok) setStats(await sRes.json());

          const fRes = await fetch("/api/console/feed?limit=30", { headers });
          if (fRes.ok) {
            const fData = await fRes.json();
            setFeed(fData.items || []);
          }

          const hRes = await fetch("/api/console/held", { headers });
          if (hRes.ok) {
            const hData = await hRes.json();
            setHeldItems(hData.items || []);
          }

          const tRes = await fetch("/api/console/tools", { headers });
          if (tRes.ok) {
            const tData = await tRes.json();
            setTools(tData.tools || []);
          }

          const pRes = await fetch("/api/console/policies", { headers });
          if (pRes.ok) setPolicies(await pRes.json());

          const aRes = await fetch("/api/console/audit", { headers });
          if (aRes.ok) setAuditStatus(await aRes.json());
        } catch (err) {
          console.error("Data refresh error:", err);
        }
      };

      useEffect(() => {
        fetchAllData();
        const timer = setInterval(fetchAllData, 4000);
        return () => clearInterval(timer);
      }, [role]);

      const handleHeldAction = async (authReqId, action, isSensitive) => {
        if (action === "approve" && isSensitive) {
          setTotpModal({ authReqId, action });
          setTotpCode("");
          return;
        }

        executeResolve(authReqId, action, "");
      };

      const executeResolve = async (authReqId, action, code) => {
        const formData = new FormData();
        formData.append("action", action);
        if (code) formData.append("totp_code", code);

        try {
          const res = await fetch(`/api/console/held/${authReqId}/action`, {
            method: "POST",
            headers: { "x-user-role": role },
            body: formData,
          });
          const data = await res.json();
          if (res.ok) {
            showToast(`Call ${authReqId} successfully ${action}d!`);
            setTotpModal(null);
            fetchAllData();
          } else {
            showToast(data.detail || "Action failed", "error");
          }
        } catch (e) {
          showToast("Network error", "error");
        }
      };

      const handleReapproveTool = async (tool) => {
        const formData = new FormData();
        formData.append("tool_name", tool.tool_name);
        formData.append("server_uri", tool.server_uri);
        formData.append("description", tool.description);

        try {
          const res = await fetch("/api/console/tools/approve", {
            method: "POST",
            headers: { "x-user-role": role },
            body: formData,
          });
          if (res.ok) {
            showToast(`Tool '${tool.tool_name}' SHA-256 approved & unquarantined!`);
            fetchAllData();
          }
        } catch (e) {
          showToast("Approval failed", "error");
        }
      };

      return (
        <div style={{ display: "flex", minHeight: "100vh" }}>
          {/* Sidebar */}
          <aside style={{ width: 260, borderRight: "1px solid var(--border-color)", background: "rgba(10, 14, 23, 0.9)", padding: "24px 16px", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, paddingBottom: 24, borderBottom: "1px solid var(--border-color)", marginBottom: 20 }}>
              <div style={{ width: 36, height: 36, borderRadius: 10, background: "linear-gradient(135deg, #3b82f6, #06b6d4)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "800", fontSize: 18 }}>🛡️</div>
              <div>
                <h1 style={{ fontSize: 16, fontWeight: 700, letterSpacing: "-0.02em" }}>MCP SHIELD</h1>
                <p style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Zero-Trust Gateway</p>
              </div>
            </div>

            {/* Nav Tabs */}
            <nav style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1 }}>
              {[
                { id: "overview", label: "Overview & Telemetry", icon: "📊" },
                { id: "feed", label: "Live Decision Stream", icon: "⚡" },
                { id: "held", label: `Held Queue (${heldItems.filter(h => h.status === 'pending').length})`, icon: "✋" },
                { id: "tools", label: `Tool Registry (${tools.length})`, icon: "🧩" },
                { id: "policies", label: "ABAC Thresholds", icon: "⚖️" },
                { id: "audit", label: "Cryptographic Chain", icon: "🔗" },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "10px 14px",
                    borderRadius: 8,
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                    border: "none",
                    textAlign: "left",
                    background: activeTab === tab.id ? "rgba(59, 130, 246, 0.15)" : "transparent",
                    color: activeTab === tab.id ? "#60a5fa" : "var(--text-secondary)",
                    transition: "all 0.15s ease",
                  }}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>

            {/* RBAC Role Selector Switcher */}
            <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border-color)", borderRadius: 10, padding: 12 }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700, marginBottom: 8 }}>
                Console RBAC Role
              </div>
              <div style={{ display: "flex", gap: 4 }}>
                {["admin", "operator", "auditor"].map(r => (
                  <button
                    key={r}
                    onClick={() => { setRole(r); showToast(`Switched RBAC role to: ${r}`); }}
                    style={{
                      flex: 1,
                      padding: "6px 0",
                      fontSize: 11,
                      fontWeight: 700,
                      borderRadius: 6,
                      border: "none",
                      cursor: "pointer",
                      textTransform: "capitalize",
                      background: role === r ? "#3b82f6" : "rgba(255,255,255,0.05)",
                      color: role === r ? "white" : "var(--text-muted)",
                    }}
                  >
                    {r}
                  </button>
                ))}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                {role === "admin" && "Full administrative write & approval privileges."}
                {role === "operator" && "Can resolve held calls & clear session taints."}
                {role === "auditor" && "Read-only access to audit logs and metrics."}
              </div>
            </div>
          </aside>

          {/* Main Workspace */}
          <main style={{ flex: 1, padding: "28px 36px", overflowY: "auto" }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
              <div>
                <h2 style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.03em" }}>
                  {activeTab === "overview" && "Gateway Telemetry & Policy Health"}
                  {activeTab === "feed" && "Real-Time AI Decision Feed"}
                  {activeTab === "held" && "Human-In-The-Loop Approval Queue"}
                  {activeTab === "tools" && "Tool Integrity Catalog & Pinned Hashes"}
                  {activeTab === "policies" && "Four-Layer Authorization & Risk Tiers"}
                  {activeTab === "audit" && "Hash-Chained Audit Trail & SIEM Export"}
                </h2>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4 }}>
                  Zero-trust Policy Enforcement Point for GitHub Copilot MCP & secondary servers.
                </p>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span className="badge badge-approved" style={{ padding: "6px 12px", fontSize: 12 }}>
                  Upstream: GitHub Streamable HTTP 🟢
                </span>
                <span className="badge badge-allow" style={{ padding: "6px 12px", fontSize: 12 }}>
                  Engine: OpenJev System One 🧠
                </span>
              </div>
            </div>

            {/* TAB: Overview */}
            {activeTab === "overview" && stats && (
              <div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
                  <div className="glass-card" style={{ padding: 20 }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>TOTAL MCP REQUESTS</div>
                    <div style={{ fontSize: 32, fontWeight: 800, marginTop: 6, color: "var(--text-primary)" }}>{stats.total_requests}</div>
                    <div style={{ fontSize: 12, color: "#34d399", marginTop: 4 }}>100% cryptographically logged</div>
                  </div>

                  <div className="glass-card" style={{ padding: 20 }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>AUTO-ALLOWED</div>
                    <div style={{ fontSize: 32, fontWeight: 800, marginTop: 6, color: "#34d399" }}>
                      {stats.outcomes?.allow || 0}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Passes OPA PBAC & ABAC</div>
                  </div>

                  <div className="glass-card" style={{ padding: 20 }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>HELD CALLS PENDING</div>
                    <div style={{ fontSize: 32, fontWeight: 800, marginTop: 6, color: "#fbbf24" }}>
                      {stats.pending_held_count}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Awaiting CIBA approval</div>
                  </div>

                  <div className="glass-card" style={{ padding: 20 }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>DENIED & BLOCKED</div>
                    <div style={{ fontSize: 32, fontWeight: 800, marginTop: 6, color: "#fb7185" }}>
                      {stats.outcomes?.deny || 0}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Tokens / Boundary Violations</div>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20 }}>
                  <div className="glass-card" style={{ padding: 22 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Latency & Performance Telemetry</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
                      <div style={{ background: "rgba(255,255,255,0.02)", padding: 14, borderRadius: 8 }}>
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>p50 LATENCY</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: "#60a5fa" }}>{stats.latency?.p50_ms} ms</div>
                      </div>
                      <div style={{ background: "rgba(255,255,255,0.02)", padding: 14, borderRadius: 8 }}>
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>p95 LATENCY</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: "#f59e0b" }}>{stats.latency?.p95_ms} ms</div>
                      </div>
                      <div style={{ background: "rgba(255,255,255,0.02)", padding: 14, borderRadius: 8 }}>
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>AVG OVERHEAD</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: "#34d399" }}>{stats.latency?.avg_ms} ms</div>
                      </div>
                    </div>

                    <h4 style={{ fontSize: 14, fontWeight: 600, marginTop: 24, marginBottom: 12 }}>Top Denied Tools</h4>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {Object.entries(stats.top_denied_tools || {}).map(([tool, cnt]) => (
                        <div key={tool} style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px", background: "rgba(244,63,94,0.05)", borderRadius: 6, border: "1px solid rgba(244,63,94,0.15)" }}>
                          <code>{tool}</code>
                          <span style={{ fontWeight: 700, color: "#fb7185" }}>{cnt} denials</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="glass-card" style={{ padding: 22 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Security Shield Status</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13 }}>RFC 9449 DPoP Replay Defense</span>
                        <span className="badge badge-allow">ACTIVE</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13 }}>RFC 9396 Delegation Boundaries</span>
                        <span className="badge badge-allow">ENFORCED</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13 }}>OpenJev Fail-Safe 150ms Timeout</span>
                        <span className="badge badge-allow">ENABLED</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13 }}>Runtime Taint Tracking State</span>
                        <span className="badge badge-allow">ACTIVE</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13 }}>SHA-256 Description Pinning</span>
                        <span className="badge badge-allow">MONITORED</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB: Live Feed */}
            {activeTab === "feed" && (
              <div className="glass-card" style={{ padding: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
                  <h3 style={{ fontSize: 16, fontWeight: 700 }}>Decision Stream</h3>
                  <button className="btn btn-ghost" onClick={fetchAllData}>Refresh Feed</button>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {feed.map(item => (
                    <div key={item.request_id || item.index} style={{ padding: 14, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-color)", borderRadius: 8 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <span className={`badge badge-${item.outcome}`}>{item.outcome}</span>
                          <strong style={{ fontSize: 14 }}>{item.tool}</strong>
                          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>by <code>{item.client_id}</code></span>
                        </div>
                        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{item.latency_ms} ms</span>
                      </div>

                      <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 12, color: "var(--text-secondary)" }}>
                        <div><strong>Target:</strong> <code>{item.server}</code></div>
                        <div><strong>Task:</strong> {item.task_id}</div>
                      </div>

                      {item.scores && Object.keys(item.scores).length > 0 && (
                        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
                          {Object.entries(item.scores).map(([k, v]) => (
                            <span key={k} style={{ background: "rgba(255,255,255,0.05)", padding: "2px 6px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>
                              {k}: {typeof v === 'number' ? v.toFixed(2) : v}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB: Held Queue */}
            {activeTab === "held" && (
              <div className="glass-card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Pending CIBA Human-in-the-Loop Approvals</h3>
                {heldItems.length === 0 ? (
                  <p style={{ color: "var(--text-muted)", fontSize: 14 }}>No actions currently held for approval.</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    {heldItems.map(h => (
                      <div key={h.auth_req_id} style={{ padding: 16, background: "rgba(245,158,11,0.04)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: 8 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span className={`badge badge-${h.status}`}>{h.status}</span>
                              {h.is_sensitive && <span className="badge badge-deny">SENSITIVE STEP-UP</span>}
                              <strong style={{ fontSize: 15 }}>{h.tool}</strong>
                            </div>
                            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 6 }}>{h.task}</p>
                          </div>
                          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Expires in: {h.expires_in}s</span>
                        </div>

                        <div style={{ background: "rgba(0,0,0,0.3)", padding: 10, borderRadius: 6, margin: "10px 0", fontSize: 13, borderLeft: "3px solid #f59e0b" }}>
                          <strong>Gateway Assessment:</strong> {h.explanation}
                        </div>

                        <pre style={{ background: "rgba(0,0,0,0.4)", padding: 10, borderRadius: 6, fontSize: 11, overflowX: "auto", marginBottom: 12 }}>
                          {JSON.stringify(h.arguments, null, 2)}
                        </pre>

                        {h.status === "pending" && (
                          <div style={{ display: "flex", gap: 10 }}>
                            <button
                              className="btn btn-success"
                              onClick={() => handleHeldAction(h.auth_req_id, "approve", h.requires_step_up)}
                              disabled={role === "auditor"}
                            >
                              Approve {h.requires_step_up ? "(TOTP Required)" : "✅"}
                            </button>
                            <button
                              className="btn btn-danger"
                              onClick={() => handleHeldAction(h.auth_req_id, "deny", false)}
                              disabled={role === "auditor"}
                            >
                              Deny ❌
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB: Tools */}
            {activeTab === "tools" && (
              <div className="glass-card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Tool Integrity Catalog</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {tools.map(t => (
                    <div key={`${t.server_uri}-${t.tool_name}`} style={{ padding: 14, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-color)", borderRadius: 8 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <span className={`badge badge-${t.status}`}>{t.status}</span>
                          <strong style={{ fontSize: 14 }}>{t.tool_name}</strong>
                          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>({t.risk_tier})</span>
                        </div>
                        {t.status === "quarantined" && (
                          <button
                            className="btn btn-primary"
                            onClick={() => handleReapproveTool(t)}
                            disabled={role !== "admin"}
                          >
                            Re-Approve SHA-256
                          </button>
                        )}
                      </div>
                      <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 6 }}>{t.description}</p>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                        <strong>SHA-256:</strong> <code>{t.description_sha256}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB: Policies */}
            {activeTab === "policies" && policies && (
              <div className="glass-card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Authorization Layers & Rego Thresholds</h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
                  {Object.entries(policies.thresholds || {}).map(([tier, cfg]) => (
                    <div key={tier} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-color)", borderRadius: 8, padding: 16 }}>
                      <span className="badge badge-approved" style={{ marginBottom: 10 }}>{tier}</span>
                      <pre style={{ fontSize: 12, marginTop: 10 }}>{JSON.stringify(cfg, null, 2)}</pre>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB: Audit */}
            {activeTab === "audit" && auditStatus && (
              <div className="glass-card" style={{ padding: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                  <div>
                    <h3 style={{ fontSize: 16, fontWeight: 700 }}>Cryptographic Hash Chain & SIEM Integration</h3>
                    <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4 }}>
                      Tamper-evident SHA-256 linked log. Tampering with any record immediately invalidates the chain.
                    </p>
                  </div>
                  <a href="/api/console/audit/export" target="_blank" className="btn btn-primary">
                    Export ECS JSON
                  </a>
                </div>

                <div style={{ display: "flex", gap: 16, marginBottom: 20 }}>
                  <div style={{ flex: 1, padding: 16, background: "rgba(16,185,129,0.05)", border: "1px solid rgba(16,185,129,0.2)", borderRadius: 8 }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>CHAIN INTEGRITY</div>
                    <div style={{ fontSize: 24, fontWeight: 700, color: auditStatus.chain_valid ? "#34d399" : "#fb7185", marginTop: 4 }}>
                      {auditStatus.chain_valid ? "VERIFIED (0 errors)" : "CORRUPTED"}
                    </div>
                  </div>

                  <div style={{ flex: 1, padding: 16, background: "rgba(59,130,246,0.05)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 8 }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>RECORD COUNT</div>
                    <div style={{ fontSize: 24, fontWeight: 700, color: "#60a5fa", marginTop: 4 }}>
                      {auditStatus.records_count} records
                    </div>
                  </div>

                  <div style={{ flex: 1, padding: 16, background: "rgba(245,158,11,0.05)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: 8 }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>RECONCILIATION</div>
                    <div style={{ fontSize: 24, fontWeight: 700, color: auditStatus.reconciliation?.reconciled ? "#34d399" : "#fbbf24", marginTop: 4 }}>
                      {auditStatus.reconciliation?.reconciled ? "100% MATCH" : "DELTA PENDING"}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </main>

          {/* Modal: TOTP Step-up */}
          {totpModal && (
            <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
              <div className="glass-card" style={{ width: 400, padding: 24, background: "#111827" }}>
                <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>⚠️ Sensitive Operation Step-Up</h3>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 16 }}>
                  Enter your 6-digit TOTP code to authorize execution:
                </p>
                <input
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={totpCode}
                  onChange={e => setTotpCode(e.target.value)}
                  style={{ width: "100%", padding: 12, fontSize: 22, letterSpacing: 8, textAlign: "center", background: "rgba(0,0,0,0.4)", border: "1px solid var(--border-color)", borderRadius: 8, color: "white", marginBottom: 16 }}
                />
                <div style={{ display: "flex", gap: 10 }}>
                  <button className="btn btn-primary" style={{ flex: 1 }} onClick={() => executeResolve(totpModal.authReqId, "approve", totpCode)}>
                    Confirm Approval
                  </button>
                  <button className="btn btn-ghost" onClick={() => setTotpModal(null)}>Cancel</button>
                </div>
              </div>
            </div>
          )}

          {/* Toast Notification */}
          {toast && (
            <div style={{ position: "fixed", bottom: 24, right: 24, background: toast.type === "error" ? "#ef4444" : "#10b981", color: "white", padding: "10px 18px", borderRadius: 8, fontWeight: 600, fontSize: 13, boxShadow: "0 4px 14px rgba(0,0,0,0.3)" }}>
              {toast.msg}
            </div>
          )}
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById("root")).render(<App />);
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
