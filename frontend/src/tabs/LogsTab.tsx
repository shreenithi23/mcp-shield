import React, { useEffect, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { AuditRecord, EvalResults } from "../types";
import {
  fetchAccessLog,
  fetchAuditFeed,
  fetchAuditStatus,
  fetchEvalResults,
  restoreAuditChain,
  tamperAuditRecord,
} from "../api";

export const LogsTab: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<"audit" | "access" | "eval">("audit");

  // Audit state
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainDetails, setChainDetails] = useState<any>(null);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [auditMessage, setAuditMessage] = useState<string | null>(null);

  // Access log state
  const [accessLogs, setAccessLogs] = useState<any[]>([]);
  const [filterOutcome, setFilterOutcome] = useState<string>("");
  const [filterTool, setFilterTool] = useState<string>("");
  const [autoRefreshAccess, setAutoRefreshAccess] = useState<boolean>(false);

  // Eval results state
  const [evalData, setEvalData] = useState<EvalResults | null>(null);

  const loadAuditData = async () => {
    try {
      const [feed, status] = await Promise.all([
        fetchAuditFeed(30),
        fetchAuditStatus(),
      ]);
      setAuditRecords(feed);
      if (status) {
        setChainValid(status.chain_valid);
        setChainDetails(status);
      }
    } catch (e) {
      console.error("Audit load error", e);
    }
  };

  const loadAccessData = async () => {
    try {
      const logs = await fetchAccessLog(filterOutcome || undefined, filterTool || undefined, 200);
      setAccessLogs(logs);
    } catch (e) {
      console.error("Access log load error", e);
    }
  };

  const loadEvalData = async () => {
    try {
      const data = await fetchEvalResults();
      setEvalData(data);
    } catch (e) {
      console.error("Eval data load error", e);
    }
  };

  useEffect(() => {
    loadAuditData();
    loadAccessData();
    loadEvalData();
  }, []);

  // Polling for access log if auto-refresh is enabled
  useEffect(() => {
    if (!autoRefreshAccess) return;
    const interval = setInterval(loadAccessData, 2000);
    return () => clearInterval(interval);
  }, [autoRefreshAccess, filterOutcome, filterTool]);

  const handleVerifyChain = async () => {
    setVerifying(true);
    setAuditMessage(null);
    try {
      const status = await fetchAuditStatus();
      setChainValid(status.chain_valid);
      setChainDetails(status);
      if (status.chain_valid) {
        setAuditMessage(`Cryptographic verification PASSED: All ${status.records_count} records valid.`);
      } else {
        setAuditMessage(`TAMPERING DETECTED! ${status.verification_error}`);
      }
    } catch (e: any) {
      setAuditMessage(`Verification error: ${e.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleTamperRecord = async () => {
    try {
      const res = await tamperAuditRecord();
      setAuditMessage(res.message);
      await loadAuditData();
      // Immediately verify to show the red failure
      const status = await fetchAuditStatus();
      setChainValid(status.chain_valid);
      setChainDetails(status);
    } catch (e: any) {
      setAuditMessage(`Tamper failed: ${e.message}`);
    }
  };

  const handleRestoreChain = async () => {
    try {
      const res = await restoreAuditChain();
      setAuditMessage(res.message);
      await loadAuditData();
      const status = await fetchAuditStatus();
      setChainValid(status.chain_valid);
      setChainDetails(status);
    } catch (e: any) {
      setAuditMessage(`Restore failed: ${e.message}`);
    }
  };

  return (
    <div>
      {/* Sub-navigation inside Logs & Results */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
        <button
          className={activeSubTab === "audit" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveSubTab("audit")}
        >
          Cryptographic Audit Log
        </button>
        <button
          className={activeSubTab === "access" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveSubTab("access")}
        >
          access.log Viewer
        </button>
        <button
          className={activeSubTab === "eval" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveSubTab("eval")}
        >
          Evaluation & ROC Chart
        </button>
      </div>

      {/* ---------------- SUB-TAB 1: AUDIT LOG ---------------- */}
      {activeSubTab === "audit" && (
        <div>
          <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div className="card-title" style={{ marginBottom: "2px" }}>
                Tamper-Evident SHA-256 Hash Chained Audit Trail
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Cryptographic back-pointers: SHA-256(prev_hash + canonical_payload)
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <button
                className="btn-primary"
                onClick={handleVerifyChain}
                disabled={verifying}
              >
                {verifying ? "Verifying..." : "Verify Chain"}
              </button>

              <button className="btn-warning" onClick={handleTamperRecord}>
                Tamper with Record
              </button>

              <button className="btn-success" onClick={handleRestoreChain}>
                Restore Chain
              </button>
            </div>
          </div>

          {/* Verification Status Alert */}
          {chainValid !== null && (
            <div
              style={{
                padding: "12px 16px",
                borderRadius: "6px",
                marginBottom: "14px",
                backgroundColor: chainValid ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.2)",
                border: `1px solid ${chainValid ? "#10b981" : "#ef4444"}`,
                color: chainValid ? "#34d399" : "#f87171",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div>
                <strong>{chainValid ? "CHAIN INTEGRITY VERIFIED (OK)" : "CHAIN INTEGRITY COMPROMISED!"}</strong>
                <div style={{ fontSize: "12px", marginTop: "2px" }}>
                  {auditMessage || (chainValid ? "Zero record modifications detected." : chainDetails?.verification_error)}
                </div>
              </div>
              <span className={`badge ${chainValid ? "badge-allow" : "badge-deny"}`}>
                {chainValid ? "INTEGRITY 100%" : "HASH MISMATCH"}
              </span>
            </div>
          )}

          {/* Audit Chain Table */}
          <div className="card">
            <div className="card-title">Recent Audit Records ({auditRecords.length})</div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Index</th>
                    <th>Timestamp</th>
                    <th>Tool</th>
                    <th>Outcome</th>
                    <th>Previous Hash Pointer</th>
                    <th>Record Hash (SHA-256)</th>
                  </tr>
                </thead>
                <tbody>
                  {auditRecords.map((rec) => (
                    <tr key={`${rec.index}-${rec.record_hash}`}>
                      <td style={{ fontWeight: 600 }}>{rec.index}</td>
                      <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                        {rec.ts.slice(11, 19)}
                      </td>
                      <td>
                        <code style={{ color: "#38bdf8" }}>{rec.tool}</code>
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            rec.outcome === "allow"
                              ? "badge-allow"
                              : rec.outcome === "hold"
                              ? "badge-hold"
                              : "badge-deny"
                          }`}
                        >
                          {rec.outcome}
                        </span>
                      </td>
                      <td>
                        <code style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                          {rec.prev_hash.slice(0, 14)}...
                        </code>
                      </td>
                      <td>
                        <code style={{ fontSize: "11px", color: "#a78bfa" }}>
                          {rec.record_hash.slice(0, 14)}...
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ---------------- SUB-TAB 2: ACCESS.LOG ---------------- */}
      {activeSubTab === "access" && (
        <div>
          <div className="card">
            <div className="card-title">
              <span>access.log Live Tail (Zero Secret Leakage)</span>
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <label style={{ fontSize: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <input
                    type="checkbox"
                    checked={autoRefreshAccess}
                    onChange={(e) => setAutoRefreshAccess(e.target.checked)}
                  />
                  Auto-refresh (2s)
                </label>
                <button className="btn-secondary" onClick={loadAccessData}>
                  Refresh Now
                </button>
              </div>
            </div>

            {/* Filter controls */}
            <div style={{ display: "flex", gap: "12px", marginBottom: "12px", flexWrap: "wrap" }}>
              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block" }}>
                  Filter by Outcome:
                </label>
                <select
                  value={filterOutcome}
                  onChange={(e) => setFilterOutcome(e.target.value)}
                  style={{ width: "140px" }}
                >
                  <option value="">All Outcomes</option>
                  <option value="allow">allow</option>
                  <option value="hold">hold</option>
                  <option value="deny">deny</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block" }}>
                  Filter by Tool:
                </label>
                <input
                  type="text"
                  placeholder="e.g. list_issues"
                  value={filterTool}
                  onChange={(e) => setFilterTool(e.target.value)}
                  style={{ width: "160px" }}
                />
              </div>
            </div>

            {/* Structured Log Lines */}
            <div
              className="code-box"
              style={{ maxHeight: "450px", overflowY: "auto", fontSize: "11px", lineHeight: "1.6" }}
            >
              {accessLogs.length === 0 ? (
                <div style={{ color: "var(--text-dim)" }}>No matching access log lines.</div>
              ) : (
                accessLogs.map((log, idx) => (
                  <div key={idx} style={{ borderBottom: "1px solid #1a2234", padding: "3px 0" }}>
                    <span style={{ color: "#64748b" }}>{log.ts?.slice(11, 19)} </span>
                    <span style={{ color: "#38bdf8", fontWeight: 600 }}>{log.method} </span>
                    <span style={{ color: "#e2e8f0" }}>{log.path} </span>
                    <span
                      style={{
                        color:
                          log.outcome === "allow"
                            ? "#10b981"
                            : log.outcome === "hold"
                            ? "#f59e0b"
                            : "#ef4444",
                        fontWeight: 600,
                      }}
                    >
                      [{log.outcome?.toUpperCase()}]
                    </span>
                    {log.tool && <span style={{ color: "#a78bfa" }}> tool={log.tool}</span>}
                    {log.reason_code && <span style={{ color: "#94a3b8" }}> reason={log.reason_code}</span>}
                    <span style={{ color: "#475569" }}> ({log.latency_ms}ms)</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* ---------------- SUB-TAB 3: EVAL RESULTS & ROC CHART ---------------- */}
      {activeSubTab === "eval" && evalData && (
        <div>
          {/* Recharts Scatter / Line Chart */}
          <div className="card">
            <div className="card-title">
              <span>Model Evaluation: Block Rate vs. False-Block Rate (ROC Curve)</span>
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                300 Labeled Benchmark Calls
              </span>
            </div>

            <div style={{ width: "100%", height: 320, marginTop: "10px" }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={evalData.chart_data} margin={{ top: 10, right: 30, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="fpr"
                    stroke="#94a3b8"
                    label={{ value: "False-Block Rate (FPR)", position: "insideBottom", offset: -10, fill: "#94a3b8" }}
                  />
                  <YAxis
                    domain={[0, 1.05]}
                    stroke="#94a3b8"
                    label={{ value: "Attack Block Rate (TPR)", angle: -90, position: "insideLeft", fill: "#94a3b8" }}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155", color: "#f8fafc" }}
                  />
                  <Legend verticalAlign="top" height={36} />
                  <Line
                    type="monotone"
                    dataKey="Jev"
                    stroke="#3b82f6"
                    strokeWidth={3}
                    dot={{ r: 4 }}
                    name="OpenJev System One (AUC: 0.994)"
                  />
                  <Line
                    type="monotone"
                    dataKey="Decision1"
                    stroke="#10b981"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                    name="Microsoft-Decision-1 (AUC: 0.991)"
                  />
                  <Line
                    type="monotone"
                    dataKey="Baseline"
                    stroke="#94a3b8"
                    strokeWidth={2}
                    strokeDasharray="5 5"
                    name="General-LLM Baseline (AUC: 0.892)"
                  />
                  {/* Mark chosen operating threshold */}
                  <ReferenceDot
                    x={evalData.operating_point.fpr}
                    y={evalData.operating_point.tpr}
                    r={6}
                    fill="#f59e0b"
                    stroke="#ffffff"
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "8px", textAlign: "center" }}>
              ★ <strong style={{ color: "#f59e0b" }}>Chosen Operating Point: </strong>
              Tier 2 Intent Threshold ≥ 0.90 / Write In Taint Hold (99.5% block rate at 1.2% false-block).
            </div>
          </div>

          {/* Comparative Metrics Table */}
          <div className="card">
            <div className="card-title">
              <span>Benchmark Performance Comparison</span>
              <a
                href={evalData.report_url}
                target="_blank"
                rel="noreferrer"
                style={{ fontSize: "12px", color: "#38bdf8", textDecoration: "none" }}
              >
                View Full REPORT.md ↗
              </a>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Jev (OpenJev System One)</th>
                    <th>Microsoft-Decision-1</th>
                    <th>General-LLM Baseline</th>
                  </tr>
                </thead>
                <tbody>
                  {evalData.metrics_table.map((row) => (
                    <tr key={row.metric}>
                      <td style={{ fontWeight: 600 }}>{row.metric}</td>
                      <td style={{ color: "#38bdf8", fontWeight: 700 }}>{row.jev}</td>
                      <td style={{ color: "#10b981", fontWeight: 600 }}>{row.decision1}</td>
                      <td style={{ color: "var(--text-muted)" }}>{row.baseline}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
