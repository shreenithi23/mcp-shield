import React, { useEffect, useState } from "react";
import type { HeldCall } from "../types";
import { clearSessionTaint, fetchHeldQueue, resolveHeldCall } from "../api";

interface Props {
  sessionId: string;
  isTainted: boolean;
  refreshSession: () => Promise<void>;
}

export const ApprovalsTab: React.FC<Props> = ({ sessionId, isTainted, refreshSession }) => {
  const [heldCalls, setHeldCalls] = useState<HeldCall[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadQueue = async () => {
    try {
      const items = await fetchHeldQueue();
      setHeldCalls(items);
    } catch (e) {
      // ignore background poll error
    }
  };

  // Poll every 2 seconds as specified
  useEffect(() => {
    loadQueue();
    const interval = setInterval(loadQueue, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleAction = async (authReqId: string, action: "approve" | "deny") => {
    setLoading(true);
    setActionNotice(null);
    try {
      const totp = totpCodes[authReqId] || "";
      const res = await resolveHeldCall(authReqId, action, totp);
      setActionNotice(`Request ${authReqId} successfully ${action}d! (${res.status})`);
      await loadQueue();
      await refreshSession();
    } catch (e: any) {
      setActionNotice(`Error: ${e.message || "Failed to resolve request"}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClearTaint = async () => {
    await clearSessionTaint(sessionId);
    await refreshSession();
    setActionNotice("Session taint successfully cleared by administrator.");
  };

  return (
    <div>
      {/* Header Bar */}
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div className="card-title" style={{ marginBottom: "2px" }}>
            Held Approvals Queue (CIBA Human-in-the-Loop)
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            Polling every 2s for held tool calls requiring human authorization
          </div>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          {isTainted && (
            <button className="btn-warning" onClick={handleClearTaint}>
              Clear Session Taint
            </button>
          )}
          <button className="btn-secondary" onClick={loadQueue}>
            Refresh Queue ({heldCalls.length})
          </button>
        </div>
      </div>

      {actionNotice && (
        <div
          style={{
            padding: "10px 14px",
            borderRadius: "6px",
            marginBottom: "14px",
            backgroundColor: actionNotice.startsWith("Error") ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.2)",
            color: actionNotice.startsWith("Error") ? "#ef4444" : "#10b981",
            border: `1px solid ${actionNotice.startsWith("Error") ? "#ef4444" : "#10b981"}`,
            fontSize: "13px",
          }}
        >
          {actionNotice}
        </div>
      )}

      {/* Queue Cards */}
      {heldCalls.length === 0 ? (
        <div className="card" style={{ textAlign: "center", padding: "40px", color: "var(--text-dim)" }}>
          Queue is empty. No tool calls currently held for approval.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {heldCalls.map((req) => (
            <div
              key={req.auth_req_id}
              className="card"
              style={{
                borderLeft: req.is_sensitive ? "4px solid #f59e0b" : "4px solid #3b82f6",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                <div>
                  <span className="badge badge-hold" style={{ marginRight: "8px" }}>
                    {req.status.toUpperCase()}
                  </span>
                  {req.is_sensitive && (
                    <span className="badge badge-deny" style={{ marginRight: "8px" }}>
                      SENSITIVE / STEP-UP REQUIRED
                    </span>
                  )}
                  <span style={{ fontSize: "12px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    id: {req.auth_req_id}
                  </span>
                </div>
                <span style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                  Expires in: {req.expires_in}s
                </span>
              </div>

              <div style={{ marginBottom: "10px" }}>
                <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>User Instruction / Task:</div>
                <div style={{ fontWeight: 600, color: "#ffffff", fontSize: "13px" }}>{req.task}</div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "10px", marginBottom: "12px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Proposed Tool Action:</div>
                  <code style={{ color: "#38bdf8", fontWeight: 700, fontSize: "13px" }}>{req.tool}</code>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                    Agent: {req.client_id}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Arguments:</div>
                  <div className="code-box" style={{ maxHeight: "70px", overflowY: "auto", fontSize: "11px" }}>
                    {JSON.stringify(req.arguments, null, 2)}
                  </div>
                </div>
              </div>

              {/* Plain English explanation */}
              {req.explanation && (
                <div
                  style={{
                    background: "rgba(245, 158, 11, 0.1)",
                    border: "1px solid rgba(245, 158, 11, 0.3)",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    color: "#fef3c7",
                    marginBottom: "12px",
                  }}
                >
                  <strong>Why this call was held: </strong>
                  {req.explanation}
                </div>
              )}

              {/* Action Controls */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: "10px",
                  borderTop: "1px solid var(--border-color)",
                  paddingTop: "12px",
                }}
              >
                {req.requires_step_up ? (
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <label style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      TOTP 6-digit Code:
                    </label>
                    <input
                      type="text"
                      maxLength={6}
                      placeholder="e.g. 123456"
                      style={{ width: "110px", textAlign: "center", letterSpacing: "2px", fontWeight: 700 }}
                      value={totpCodes[req.auth_req_id] || ""}
                      onChange={(e) =>
                        setTotpCodes({ ...totpCodes, [req.auth_req_id]: e.target.value })
                      }
                    />
                    <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                      (Default dev key: accepted)
                    </span>
                  </div>
                ) : (
                  <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    Standard authorization (No step-up required)
                  </span>
                )}

                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    className="btn-danger"
                    onClick={() => handleAction(req.auth_req_id, "deny")}
                    disabled={loading || req.status !== "pending"}
                  >
                    Deny
                  </button>
                  <button
                    className="btn-success"
                    onClick={() => handleAction(req.auth_req_id, "approve")}
                    disabled={loading || req.status !== "pending"}
                  >
                    Approve
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
