import React, { useEffect, useState } from "react";
import type { AgentClient, DecodedToken, UserSession } from "./types";
import { getSessionStatus, loginUser } from "./api";
import { AgentRunTab } from "./tabs/AgentRunTab";
import { TokensTab } from "./tabs/TokensTab";
import { ApprovalsTab } from "./tabs/ApprovalsTab";
import { ToolsTab } from "./tabs/ToolsTab";
import { LogsTab } from "./tabs/LogsTab";

type TabId = "run" | "tokens" | "approvals" | "tools" | "logs";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>("run");
  const [user, setUser] = useState<UserSession | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [decodedToken, setDecodedToken] = useState<DecodedToken | null>(null);
  const [agentClient, setAgentClient] = useState<AgentClient | null>({
    client_id: "agent_copilot_assistant",
    client_name: "GitHub Copilot Bug Assistant",
  });
  const [sessionId] = useState<string>("session-demo-01");
  const [isTainted, setIsTainted] = useState<boolean>(false);
  const [currentTask, setCurrentTask] = useState<string>(
    "Summarize open issues on repo and post triage update to Slack channel"
  );

  // Auto-login on load so demo is immediately live and populated
  useEffect(() => {
    loginUser("alice_dev", "admin")
      .then((res) => {
        setUser(res.user);
        setToken(res.token);
        setDecodedToken(res.decoded);
      })
      .catch((e) => console.log("Initial auto-login waiting for user:", e));
  }, []);

  const refreshSession = async () => {
    try {
      const status = await getSessionStatus(sessionId);
      setIsTainted(status.tainted);
    } catch (e) {
      // ignore
    }
  };

  useEffect(() => {
    refreshSession();
  }, [sessionId]);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* ---------------- Top Header ---------------- */}
      <header
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border-color)",
          padding: "12px 24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "20px" }}>🛡️</span>
            <div>
              <div style={{ fontSize: "16px", fontWeight: 700, color: "#ffffff", letterSpacing: "0.02em" }}>
                MCP SHIELD
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                Zero-Trust PEP Gateway for AI Tool Servers
              </div>
            </div>
          </div>

          {/* Session State Badge */}
          <div style={{ marginLeft: "14px" }}>
            {isTainted ? (
              <span className="badge badge-tainted">⚠️ SESSION TAINTED (READ-ONLY)</span>
            ) : (
              <span className="badge badge-normal">● SESSION NORMAL</span>
            )}
          </div>
        </div>

        {/* Current User and Task Indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", maxWidth: "340px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            <span style={{ color: "var(--text-dim)" }}>Task: </span>
            <strong style={{ color: "#e2e8f0" }}>{currentTask}</strong>
          </div>

          <div
            style={{
              background: "#0f172a",
              border: "1px solid var(--border-color)",
              padding: "4px 10px",
              borderRadius: "6px",
              fontSize: "12px",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <span style={{ color: "#34d399" }}>👤</span>
            <span style={{ color: "#ffffff", fontWeight: 600 }}>{user?.name || "Not Logged In"}</span>
            <span style={{ fontSize: "10px", background: "#1e293b", padding: "1px 5px", borderRadius: "3px", color: "var(--text-muted)" }}>
              {user?.role || "guest"}
            </span>
          </div>
        </div>
      </header>

      {/* ---------------- 5 Navigation Tabs ---------------- */}
      <nav
        style={{
          backgroundColor: "#0d1320",
          borderBottom: "1px solid var(--border-color)",
          padding: "0 24px",
          display: "flex",
          gap: "4px",
        }}
      >
        <button
          onClick={() => setActiveTab("run")}
          style={{
            background: "transparent",
            color: activeTab === "run" ? "#38bdf8" : "var(--text-muted)",
            borderBottom: activeTab === "run" ? "2px solid #38bdf8" : "2px solid transparent",
            borderRadius: 0,
            padding: "12px 18px",
            fontWeight: 600,
          }}
        >
          1. Agent Run
        </button>

        <button
          onClick={() => setActiveTab("tokens")}
          style={{
            background: "transparent",
            color: activeTab === "tokens" ? "#38bdf8" : "var(--text-muted)",
            borderBottom: activeTab === "tokens" ? "2px solid #38bdf8" : "2px solid transparent",
            borderRadius: 0,
            padding: "12px 18px",
            fontWeight: 600,
          }}
        >
          2. Tokens
        </button>

        <button
          onClick={() => setActiveTab("approvals")}
          style={{
            background: "transparent",
            color: activeTab === "approvals" ? "#38bdf8" : "var(--text-muted)",
            borderBottom: activeTab === "approvals" ? "2px solid #38bdf8" : "2px solid transparent",
            borderRadius: 0,
            padding: "12px 18px",
            fontWeight: 600,
          }}
        >
          3. Approvals
        </button>

        <button
          onClick={() => setActiveTab("tools")}
          style={{
            background: "transparent",
            color: activeTab === "tools" ? "#38bdf8" : "var(--text-muted)",
            borderBottom: activeTab === "tools" ? "2px solid #38bdf8" : "2px solid transparent",
            borderRadius: 0,
            padding: "12px 18px",
            fontWeight: 600,
          }}
        >
          4. Tools & Policy
        </button>

        <button
          onClick={() => setActiveTab("logs")}
          style={{
            background: "transparent",
            color: activeTab === "logs" ? "#38bdf8" : "var(--text-muted)",
            borderBottom: activeTab === "logs" ? "2px solid #38bdf8" : "2px solid transparent",
            borderRadius: 0,
            padding: "12px 18px",
            fontWeight: 600,
          }}
        >
          5. Logs & Results
        </button>
      </nav>

      {/* ---------------- Main Content Body ---------------- */}
      <main style={{ flex: 1, padding: "24px", maxWidth: "1280px", width: "100%", margin: "0 auto" }}>
        {activeTab === "run" && (
          <AgentRunTab
            user={user}
            setUser={setUser}
            token={token}
            setToken={setToken}
            decodedToken={decodedToken}
            setDecodedToken={setDecodedToken}
            agentClient={agentClient}
            setAgentClient={setAgentClient}
            sessionId={sessionId}
            isTainted={isTainted}
            setIsTainted={setIsTainted}
            currentTask={currentTask}
            setCurrentTask={setCurrentTask}
            refreshSession={refreshSession}
          />
        )}

        {activeTab === "tokens" && (
          <TokensTab
            token={token}
            decodedToken={decodedToken}
            onTokenRevoked={() => {
              setToken(null);
              setDecodedToken(null);
            }}
          />
        )}

        {activeTab === "approvals" && (
          <ApprovalsTab
            sessionId={sessionId}
            isTainted={isTainted}
            refreshSession={refreshSession}
          />
        )}

        {activeTab === "tools" && <ToolsTab />}

        {activeTab === "logs" && <LogsTab />}
      </main>
    </div>
  );
};

export default App;
