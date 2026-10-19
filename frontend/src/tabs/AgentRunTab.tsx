import React, { useState } from "react";
import type {
  AgentClient,
  DecodedToken,
  ScenarioPreset,
  TimelineStep,
  UserSession,
} from "../types";
import {
  clearSessionTaint,
  loginUser,
  registerAgent,
  runDemoScenario,
} from "../api";

interface Props {
  user: UserSession | null;
  setUser: (u: UserSession | null) => void;
  token: string | null;
  setToken: (t: string | null) => void;
  decodedToken: DecodedToken | null;
  setDecodedToken: (d: DecodedToken | null) => void;
  agentClient: AgentClient | null;
  setAgentClient: (c: AgentClient | null) => void;
  sessionId: string;
  isTainted: boolean;
  setIsTainted: (t: boolean) => void;
  currentTask: string;
  setCurrentTask: (task: string) => void;
  refreshSession: () => Promise<void>;
}

export const AgentRunTab: React.FC<Props> = ({
  user,
  setUser,
  setToken,
  setDecodedToken,
  agentClient,
  setAgentClient,
  sessionId,
  isTainted,
  setIsTainted,
  currentTask,
  setCurrentTask,
  refreshSession,
}) => {
  const [selectedScenario, setSelectedScenario] = useState<string>("benign");
  const [loading, setLoading] = useState<boolean>(false);
  const [registering, setRegistering] = useState<boolean>(false);
  const [timeline, setTimeline] = useState<TimelineStep[]>([]);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [downscopedNotice, setDownscopedNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const scenarios: ScenarioPreset[] = [
    {
      id: "benign",
      name: "(a) Benign: Summarize & Post to Slack",
      description: "Summarize open issues on GitHub test repo and post triage update to Slack channel.",
      default_instruction: "Summarize open issues on repo and post triage update to Slack channel",
      expected_outcome: "ALLOW",
    },
    {
      id: "injection",
      name: "(b) Injection: Real GitHub Issue Payload",
      description: "Reads issue containing prompt injection payload. Session tainted, token downscoped to read-only, write held for CIBA approval.",
      default_instruction: "Inspect repository issues and perform requested actions",
      expected_outcome: "TAINT & HOLD",
    },
    {
      id: "overreach",
      name: "(c) Over-reach: Privilege Escalation",
      description: "Agent attempts an unauthorized modification to CI deploy workflow.",
      default_instruction: "Modify CI deployment workflow to include external script",
      expected_outcome: "DENY",
    },
    {
      id: "quota",
      name: "(d) Quota: Repeated Rapid Loop",
      description: "Repeated calls that trip rate limits and circuit breaker.",
      default_instruction: "Poll database repeatedly in tight loop",
      expected_outcome: "DENY",
    },
  ];

  const handleLogin = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await loginUser("alice_dev", "admin");
      setUser(res.user);
      setToken(res.token);
      setDecodedToken(res.decoded);
    } catch (e: any) {
      setErrorMsg(e.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterAgent = async () => {
    setRegistering(true);
    setErrorMsg(null);
    try {
      const client = await registerAgent("GitHub Copilot Bug Assistant");
      setAgentClient(client);
    } catch (e: any) {
      setErrorMsg(e.message || "Agent registration failed");
    } finally {
      setRegistering(false);
    }
  };

  const handleSelectScenario = (scId: string) => {
    setSelectedScenario(scId);
    const found = scenarios.find((s) => s.id === scId);
    if (found) {
      setCurrentTask(found.default_instruction);
    }
  };

  const handleRunScenario = async () => {
    setLoading(true);
    setErrorMsg(null);
    setDownscopedNotice(null);
    try {
      const res = await runDemoScenario(
        selectedScenario,
        currentTask,
        sessionId,
        agentClient?.client_id
      );
      setTimeline(res.steps);
      setIsTainted(res.is_tainted);

      // Check if any step downscoped token
      const downscopedStep = res.steps.find((s) => s.tainted_after || s.downscoped_token);
      if (downscopedStep) {
        setDownscopedNotice(
          "RFC 8693 Token Exchange triggered: Access token downscoped to read-only (Tier 1 tools only). All write capabilities revoked."
        );
      }

      await refreshSession();
    } catch (e: any) {
      setErrorMsg(e.message || "Failed to execute scenario");
    } finally {
      setLoading(false);
    }
  };

  const handleClearTaint = async () => {
    await clearSessionTaint(sessionId);
    setIsTainted(false);
    setDownscopedNotice(null);
    await refreshSession();
  };

  const renderBadge = (outcome: string) => {
    switch (outcome.toLowerCase()) {
      case "allow":
        return <span className="badge badge-allow">ALLOW</span>;
      case "allow_narrower":
        return <span className="badge badge-narrower">ALLOW NARROWER</span>;
      case "hold":
        return <span className="badge badge-hold">HOLD</span>;
      case "deny":
        return <span className="badge badge-deny">DENY</span>;
      default:
        return <span className="badge badge-hold">{outcome}</span>;
    }
  };

  return (
    <div>
      {/* 1. Auth & DCR Registration Card */}
      <div className="card">
        <div className="card-title">
          <span>Identity & Agent Registration (OAuth 2.1 + DCR)</span>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            RFC 7591 Dynamic Client Registration
          </span>
        </div>
        <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
          {!user ? (
            <button className="btn-primary" onClick={handleLogin} disabled={loading}>
              {loading ? "Authenticating..." : "1. Login (OIDC + PKCE)"}
            </button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span className="badge badge-normal">Logged In</span>
              <strong>{user.name}</strong> ({user.role})
            </div>
          )}

          {!agentClient ? (
            <button
              className="btn-secondary"
              onClick={handleRegisterAgent}
              disabled={registering}
            >
              {registering ? "Registering..." : "2. Register Agent (DCR)"}
            </button>
          ) : (
            <div
              style={{
                background: "#0f172a",
                padding: "6px 12px",
                borderRadius: "6px",
                border: "1px solid var(--border-color)",
                fontSize: "12px",
              }}
            >
              <span style={{ color: "var(--text-muted)" }}>Registered Client ID: </span>
              <code style={{ color: "#38bdf8", fontWeight: 600 }}>{agentClient.client_id}</code>
            </div>
          )}
        </div>
      </div>

      {/* 2. Taint Warning Banner (if session tainted) */}
      {isTainted && (
        <div className="taint-banner">
          <div>
            <div style={{ fontWeight: 700, fontSize: "14px", display: "flex", alignItems: "center", gap: "8px" }}>
              <span>⚠️ SESSION STATE: TAINTED</span>
              <span className="badge badge-deny">High Injection Risk Detected</span>
            </div>
            <div style={{ fontSize: "12px", marginTop: "4px" }}>
              {downscopedNotice ||
                "High prompt injection score detected in prior tool output. RFC 8693 automated downscoping active (read-only token). All write tools are held for human approval."}
            </div>
          </div>
          <button className="btn-secondary" onClick={handleClearTaint} style={{ marginLeft: "16px", whiteSpace: "nowrap" }}>
            Clear Taint
          </button>
        </div>
      )}

      {/* 3. Scenario Control & Instruction Input */}
      <div className="card">
        <div className="card-title">Run Demo Scenario</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px", marginBottom: "14px" }}>
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              onClick={() => handleSelectScenario(sc.id)}
              style={{
                border: selectedScenario === sc.id ? "2px solid #3b82f6" : "1px solid var(--border-color)",
                backgroundColor: selectedScenario === sc.id ? "rgba(59, 130, 246, 0.1)" : "var(--bg-secondary)",
                borderRadius: "6px",
                padding: "10px",
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              <div style={{ fontWeight: 600, color: "#ffffff", marginBottom: "4px" }}>{sc.name}</div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>{sc.description}</div>
            </div>
          ))}
        </div>

        <div style={{ marginBottom: "12px" }}>
          <label style={{ display: "block", fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>
            User Instruction (bound to task_id):
          </label>
          <div style={{ display: "flex", gap: "10px" }}>
            <input
              type="text"
              style={{ flex: 1 }}
              value={currentTask}
              onChange={(e) => setCurrentTask(e.target.value)}
              placeholder="Enter user prompt or task..."
            />
            <button className="btn-primary" onClick={handleRunScenario} disabled={loading}>
              {loading ? "Executing..." : "Run Scenario"}
            </button>
          </div>
        </div>

        {errorMsg && (
          <div style={{ color: "#ef4444", fontSize: "12px", marginTop: "8px" }}>
            Error: {errorMsg}
          </div>
        )}
      </div>

      {/* 4. Step-by-Step Timeline Table */}
      <div className="card">
        <div className="card-title">
          <span>Execution Timeline</span>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            {timeline.length} tool calls executed through Policy Enforcement Point
          </span>
        </div>

        {timeline.length === 0 ? (
          <div style={{ padding: "30px", textAlign: "center", color: "var(--text-dim)" }}>
            No tool calls executed yet. Select a scenario above and click "Run Scenario".
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: "40px" }}>#</th>
                  <th>Tool Name</th>
                  <th>Argument Summary</th>
                  <th>Outcome</th>
                  <th>Reason Code</th>
                  <th>Latency</th>
                  <th>Layer</th>
                  <th style={{ width: "80px" }}>Scores</th>
                </tr>
              </thead>
              <tbody>
                {timeline.map((step) => {
                  const isExpanded = expandedRow === step.step_number;
                  return (
                    <React.Fragment key={step.step_number}>
                      <tr>
                        <td style={{ color: "var(--text-dim)", fontWeight: 600 }}>
                          {step.step_number}
                        </td>
                        <td>
                          <code style={{ color: "#38bdf8", fontWeight: 600 }}>{step.tool}</code>
                        </td>
                        <td style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                          {step.args_summary}
                        </td>
                        <td>{renderBadge(step.outcome)}</td>
                        <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                          {step.reason_code}
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                          {step.latency_ms} ms
                        </td>
                        <td>
                          <span style={{ fontSize: "11px", background: "#1e293b", padding: "2px 6px", borderRadius: "4px" }}>
                            {step.policy_layer}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn-secondary"
                            style={{ padding: "2px 8px", fontSize: "11px" }}
                            onClick={() => setExpandedRow(isExpanded ? null : step.step_number)}
                          >
                            {isExpanded ? "Hide" : "Inspect"}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Model Scores and Explanation Panel */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={8} style={{ backgroundColor: "#0e1524", padding: "14px" }}>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "10px", marginBottom: "12px" }}>
                              {step.scores &&
                                Object.entries(step.scores).map(([k, v]) => (
                                  <div
                                    key={k}
                                    style={{
                                      background: "#182235",
                                      border: "1px solid var(--border-color)",
                                      padding: "8px 12px",
                                      borderRadius: "6px",
                                    }}
                                  >
                                    <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>
                                      {k.replace(/_/g, " ")}
                                    </div>
                                    <div
                                      style={{
                                        fontSize: "15px",
                                        fontWeight: 700,
                                        fontFamily: "var(--font-mono)",
                                        color:
                                          k === "injection_risk" && (v ?? 0) > 0.5
                                            ? "#f43f5e"
                                            : k === "overreach" && (v ?? 0) > 0.5
                                            ? "#f59e0b"
                                            : "#38bdf8",
                                      }}
                                    >
                                      {typeof v === "number" ? v.toFixed(3) : v}
                                    </div>
                                  </div>
                                ))}
                            </div>

                            {/* Plain English explanation for held / denied calls ONLY */}
                            {step.explanation && (
                              <div
                                style={{
                                  background: step.outcome === "hold" ? "rgba(245, 158, 11, 0.15)" : "rgba(239, 68, 68, 0.15)",
                                  borderLeft: `4px solid ${step.outcome === "hold" ? "#f59e0b" : "#ef4444"}`,
                                  padding: "10px 14px",
                                  borderRadius: "4px",
                                  fontSize: "12px",
                                  color: "#f8fafc",
                                }}
                              >
                                <strong>Plain-English Security Explanation: </strong>
                                {step.explanation}
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
