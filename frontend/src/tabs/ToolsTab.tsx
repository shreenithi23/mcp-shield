import React, { useEffect, useState } from "react";
import type { QuotaData, RegisteredTool } from "../types";
import {
  approveTool,
  fetchPolicies,
  fetchQuotas,
  fetchTools,
  resetMaliciousServer,
  simulateRugPull,
} from "../api";

export const ToolsTab: React.FC = () => {
  const [tools, setTools] = useState<RegisteredTool[]>([]);
  const [quotas, setQuotas] = useState<QuotaData | null>(null);
  const [policies, setPolicies] = useState<any>(null);
  const [rugPullData, setRugPullData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [tList, qData, pData] = await Promise.all([
        fetchTools(),
        fetchQuotas("agent_copilot_assistant"),
        fetchPolicies(),
      ]);
      setTools(tList);
      setQuotas(qData);
      setPolicies(pData);
    } catch (e: any) {
      console.error("Failed to load tools data", e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSimulateRugPull = async () => {
    setLoading(true);
    setStatusMsg(null);
    try {
      const res = await simulateRugPull();
      setRugPullData(res);
      setStatusMsg("Rug pull simulated! SHA-256 hash mismatch detected. Tool quarantined.");
      await loadData();
    } catch (e: any) {
      setStatusMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleReapprove = async (toolName: string, serverUri: string, description: string) => {
    setLoading(true);
    setStatusMsg(null);
    try {
      await approveTool(toolName, serverUri, description);
      setRugPullData(null);
      setStatusMsg(`Tool '${toolName}' re-approved with new pinned SHA-256 hash.`);
      await loadData();
    } catch (e: any) {
      setStatusMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleResetMalicious = async () => {
    setLoading(true);
    try {
      await resetMaliciousServer();
      setRugPullData(null);
      setStatusMsg("Malicious server reset to clean approved baseline.");
      await loadData();
    } catch (e: any) {
      setStatusMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {/* 1. Tool Integrity & Description Hash Pinning Table */}
      <div className="card">
        <div className="card-title">
          <span>Registered Tools & Cryptographic SHA-256 Pinning</span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="btn-danger"
              onClick={handleSimulateRugPull}
              disabled={loading}
            >
              Simulate Rug Pull (Malicious Server)
            </button>
            <button
              className="btn-secondary"
              onClick={handleResetMalicious}
              disabled={loading}
            >
              Reset Server
            </button>
          </div>
        </div>

        {statusMsg && (
          <div
            style={{
              padding: "10px 14px",
              borderRadius: "6px",
              marginBottom: "12px",
              backgroundColor: statusMsg.includes("quarantined")
                ? "rgba(225, 29, 72, 0.2)"
                : "rgba(16, 185, 129, 0.2)",
              color: statusMsg.includes("quarantined") ? "#fb7185" : "#10b981",
              border: `1px solid ${statusMsg.includes("quarantined") ? "#e11d48" : "#10b981"}`,
              fontSize: "13px",
            }}
          >
            {statusMsg}
          </div>
        )}

        {/* Rug Pull Detection Alert */}
        {rugPullData && (
          <div
            style={{
              background: "#1e1424",
              border: "1px solid #e11d48",
              borderRadius: "8px",
              padding: "14px",
              marginBottom: "16px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <div style={{ fontWeight: 700, color: "#fda4af", fontSize: "14px" }}>
                🚨 TAMPERING DETECTED: Tool Description Hash Mismatch
              </div>
              <button
                className="btn-success"
                onClick={() =>
                  handleReapprove(
                    rugPullData.tool_name,
                    rugPullData.server_uri,
                    rugPullData.mutated_description
                  )
                }
                disabled={loading}
              >
                Admin Re-Approve New Hash
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "10px", marginBottom: "10px" }}>
              <div>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Tool: </span>
                <code>{rugPullData.tool_name}</code>
              </div>
              <div>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Pinned SHA-256: </span>
                <code style={{ fontSize: "11px" }}>{rugPullData.pinned_sha256?.slice(0, 16)}...</code>
              </div>
              <div>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Mutated SHA-256: </span>
                <code style={{ fontSize: "11px", color: "#f43f5e" }}>{rugPullData.mutated_sha256?.slice(0, 16)}...</code>
              </div>
              <div>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Poisoning Risk: </span>
                <strong style={{ color: "#f43f5e" }}>{rugPullData.scores?.poisoning_risk}</strong>
              </div>
              <div>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Semantic Drift: </span>
                <strong style={{ color: "#f59e0b" }}>{rugPullData.scores?.semantic_drift}</strong>
              </div>
            </div>

            <div style={{ fontSize: "12px", color: "#fecdd3", background: "rgba(225, 29, 72, 0.2)", padding: "8px", borderRadius: "4px" }}>
              <strong>Mutated Description: </strong>
              {rugPullData.mutated_description}
            </div>
          </div>
        )}

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Tool Name</th>
                <th>Server URI</th>
                <th>Risk Tier</th>
                <th>Pinned Hash (SHA-256)</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={`${t.server_uri}:${t.tool_name}`}>
                  <td>
                    <code style={{ fontWeight: 600, color: "#38bdf8" }}>{t.tool_name}</code>
                  </td>
                  <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>{t.server_uri}</td>
                  <td>
                    <span
                      style={{
                        fontSize: "11px",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        background:
                          t.risk_tier.includes("3")
                            ? "rgba(239, 68, 68, 0.2)"
                            : t.risk_tier.includes("2")
                            ? "rgba(245, 158, 11, 0.2)"
                            : "rgba(16, 185, 129, 0.2)",
                        color:
                          t.risk_tier.includes("3")
                            ? "#ef4444"
                            : t.risk_tier.includes("2")
                            ? "#f59e0b"
                            : "#10b981",
                        fontWeight: 600,
                      }}
                    >
                      {t.risk_tier}
                    </span>
                  </td>
                  <td>
                    <code style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                      {t.description_sha256?.slice(0, 16)}...
                    </code>
                  </td>
                  <td>
                    {t.status === "approved" ? (
                      <span className="badge badge-allow">APPROVED</span>
                    ) : (
                      <span className="badge badge-deny">QUARANTINED</span>
                    )}
                  </td>
                  <td>
                    {t.status === "quarantined" ? (
                      <button
                        className="btn-success"
                        style={{ padding: "2px 8px", fontSize: "11px" }}
                        onClick={() => handleReapprove(t.tool_name, t.server_uri, t.description)}
                      >
                        Re-approve
                      </button>
                    ) : (
                      <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Pinned OK</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Quotas & Circuit Breaker Usage */}
      {quotas && (
        <div className="card">
          <div className="card-title">
            <span>Layer 3 Quotas & Circuit Breaker (Calls / Minute)</span>
            <span className="badge badge-normal">{quotas.circuit_breaker}</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "12px" }}>
            {quotas.usage.map((u) => (
              <div
                key={u.tool}
                style={{
                  background: "#0e1524",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "10px 14px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                  <code style={{ color: "#38bdf8", fontWeight: 600 }}>{u.tool}</code>
                  <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    {u.calls_last_min} / {u.limit} calls
                  </span>
                </div>

                {/* Live progress bar */}
                <div
                  style={{
                    height: "6px",
                    background: "#1e293b",
                    borderRadius: "3px",
                    overflow: "hidden",
                    marginTop: "6px",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${Math.min(100, u.percentage)}%`,
                      background: u.percentage > 80 ? "#ef4444" : "#10b981",
                      transition: "width 0.3s ease",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3. Layer 4 Threshold Configuration */}
      {policies && (
        <div className="card">
          <div className="card-title">
            <span>Layer 4 ABAC Calibrated Risk Thresholds</span>
            <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
              Package: {policies.rego_package}
            </span>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Tier</th>
                  <th>Min Intent Match</th>
                  <th>Max Overreach</th>
                  <th>Min Reversibility</th>
                  <th>Max Injection Risk</th>
                  <th>Requires CIBA</th>
                  <th>Requires TOTP</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(policies.thresholds || {}).map(([tierKey, vals]: [string, any]) => (
                  <tr key={tierKey}>
                    <td style={{ fontWeight: 600 }}>{tierKey}</td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{vals.min_intent_match}</td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{vals.max_overreach}</td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{vals.min_reversibility}</td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{vals.max_injection_risk}</td>
                    <td>{vals.requires_ciba ? "YES" : "NO"}</td>
                    <td>{vals.requires_totp ? "YES" : "NO"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
