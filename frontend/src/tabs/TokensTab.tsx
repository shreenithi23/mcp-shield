import React, { useEffect, useState } from "react";
import type { DecodedToken } from "../types";
import { introspectToken, revokeToken, testTokenRejection } from "../api";

interface Props {
  token: string | null;
  decodedToken: DecodedToken | null;
  onTokenRevoked?: () => void;
}

export const TokensTab: React.FC<Props> = ({ token, decodedToken, onTokenRevoked }) => {
  const [timeLeftSeconds, setTimeLeftSeconds] = useState<number>(300);
  const [responseLog, setResponseLog] = useState<{
    action: string;
    status: number;
    payload: any;
  } | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);

  // Live countdown timer based on exp claim or 300s window
  useEffect(() => {
    if (!decodedToken?.exp) {
      setTimeLeftSeconds(300);
      return;
    }

    const updateTimer = () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = Math.max(0, decodedToken.exp - now);
      setTimeLeftSeconds(remaining);
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [decodedToken]);

  const formatCountdown = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const rem = secs % 60;
    return `${mins}:${rem < 10 ? "0" : ""}${rem}`;
  };

  const handleWrongServer = async () => {
    setLoadingAction("wrong_server");
    try {
      const res = await testTokenRejection("wrong_server");
      setResponseLog({
        action: "Try token on wrong server (Resource Indicator mismatch)",
        status: res.http_status,
        payload: res,
      });
    } catch (e: any) {
      setResponseLog({ action: "Wrong server check", status: 500, payload: { error: e.message } });
    } finally {
      setLoadingAction(null);
    }
  };

  const handleMissingDpop = async () => {
    setLoadingAction("missing_dpop");
    try {
      const res = await testTokenRejection("missing_dpop");
      setResponseLog({
        action: "Replay without DPoP key proof (RFC 9449 violation)",
        status: res.http_status,
        payload: res,
      });
    } catch (e: any) {
      setResponseLog({ action: "DPoP check", status: 500, payload: { error: e.message } });
    } finally {
      setLoadingAction(null);
    }
  };

  const handleIntrospect = async () => {
    if (!token) return;
    setLoadingAction("introspect");
    try {
      const res = await introspectToken(token);
      setResponseLog({
        action: "Token Introspection (RFC 7662)",
        status: 200,
        payload: res,
      });
    } catch (e: any) {
      setResponseLog({ action: "Introspect", status: 500, payload: { error: e.message } });
    } finally {
      setLoadingAction(null);
    }
  };

  const handleRevoke = async () => {
    if (!token) return;
    setLoadingAction("revoke");
    try {
      const res = await revokeToken(token);
      setResponseLog({
        action: "Token Revocation (RFC 7009)",
        status: res.status,
        payload: res,
      });
      if (onTokenRevoked) onTokenRevoked();
    } catch (e: any) {
      setResponseLog({ action: "Revoke", status: 500, payload: { error: e.message } });
    } finally {
      setLoadingAction(null);
    }
  };

  if (!decodedToken) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "40px" }}>
        <div style={{ color: "var(--text-muted)", marginBottom: "12px" }}>
          No active token found in session. Please log in on the "Agent Run" tab first.
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* 1. Token Overview Header & Live Countdown */}
      <div className="card">
        <div className="card-title">
          <span>Decoded RFC 9068 / RFC 9449 Access Token</span>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Expires in:</span>
            <span
              className="badge"
              style={{
                backgroundColor: timeLeftSeconds < 60 ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.2)",
                color: timeLeftSeconds < 60 ? "#ef4444" : "#10b981",
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
              }}
            >
              ⏱ {formatCountdown(timeLeftSeconds)}
            </span>
          </div>
        </div>

        {/* Clean decoded claims display - strictly NO signatures or secret material */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px", marginBottom: "16px" }}>
          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>SUBJECT (sub)</div>
            <div style={{ fontWeight: 600, color: "#ffffff", fontFamily: "var(--font-mono)" }}>{decodedToken.sub}</div>
          </div>

          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>CLIENT ID (client_id)</div>
            <div style={{ fontWeight: 600, color: "#38bdf8", fontFamily: "var(--font-mono)" }}>{decodedToken.client_id}</div>
          </div>

          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>AUDIENCE (aud - single server)</div>
            <div style={{ fontWeight: 600, color: "#a78bfa", fontFamily: "var(--font-mono)", fontSize: "12px" }}>{decodedToken.aud}</div>
          </div>

          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>DPoP KEY THUMBPRINT (cnf.jkt)</div>
            <div style={{ fontWeight: 600, color: "#34d399", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
              {decodedToken.cnf?.jkt || "SHA-256 bound proof"}
            </div>
          </div>

          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>TASK ID (task_id)</div>
            <div style={{ color: "#e2e8f0", fontSize: "12px" }}>{decodedToken.task_id || "Unbound general task"}</div>
          </div>

          <div style={{ background: "#0e1524", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>ACTOR (act) / TOKEN JTI</div>
            <div style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
              jti: {decodedToken.jti.slice(0, 16)}...
            </div>
          </div>
        </div>

        {/* Authorization Details (RFC 9396 Rich Authorization Requests) */}
        {decodedToken.authorization_details && decodedToken.authorization_details.length > 0 && (
          <div style={{ marginTop: "12px" }}>
            <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--text-muted)", marginBottom: "6px" }}>
              AUTHORIZATION DETAILS (RFC 9396 Tool Grants):
            </div>
            <div className="code-box">
              {JSON.stringify(decodedToken.authorization_details, null, 2)}
            </div>
          </div>
        )}
      </div>

      {/* 2. Gateway Security Verification Action Buttons */}
      <div className="card">
        <div className="card-title">Gateway Security Checks & Negative Testing</div>
        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px" }}>
          <button
            className="btn-warning"
            onClick={handleWrongServer}
            disabled={loadingAction !== null}
          >
            {loadingAction === "wrong_server" ? "Testing..." : "Try token on wrong server"}
          </button>

          <button
            className="btn-warning"
            onClick={handleMissingDpop}
            disabled={loadingAction !== null}
          >
            {loadingAction === "missing_dpop" ? "Testing..." : "Replay without DPoP key"}
          </button>

          <button
            className="btn-primary"
            onClick={handleIntrospect}
            disabled={loadingAction !== null}
          >
            {loadingAction === "introspect" ? "Introspecting..." : "Introspect"}
          </button>

          <button
            className="btn-danger"
            onClick={handleRevoke}
            disabled={loadingAction !== null}
          >
            {loadingAction === "revoke" ? "Revoking..." : "Revoke token"}
          </button>
        </div>

        {/* Gateway Response Box */}
        {responseLog && (
          <div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>
              Gateway Response for: <strong>{responseLog.action}</strong> (HTTP {responseLog.status})
            </div>
            <div className="code-box" style={{ maxHeight: "240px", overflowY: "auto" }}>
              {JSON.stringify(responseLog.payload, null, 2)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
