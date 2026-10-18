"""Access Log Analyzer, Statistical Profiler, and Chain Reconciliation Tool."""

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcp_shield.audit.chain import DEFAULT_AUDIT_LOG_PATH, AuditRecord


class LogAnalysisReport:
    def __init__(self):
        self.total_requests: int = 0
        self.requests_per_tool: Counter = Counter()
        self.outcome_breakdown: Counter = Counter()
        self.denied_reasons: Counter = Counter()
        self.top_denied_tools: Counter = Counter()
        self.latencies: List[float] = []
        self.anomalies: List[Dict[str, Any]] = []
        self.reconciliation: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        p50 = statistics.median(self.latencies) if self.latencies else 0.0
        p95 = statistics.quantiles(self.latencies, n=20)[18] if len(self.latencies) >= 20 else (max(self.latencies) if self.latencies else 0.0)
        avg = statistics.mean(self.latencies) if self.latencies else 0.0

        return {
            "total_requests": self.total_requests,
            "requests_per_tool": dict(self.requests_per_tool.most_common(15)),
            "outcome_breakdown": dict(self.outcome_breakdown),
            "top_denied_tools": dict(self.top_denied_tools.most_common(10)),
            "top_denial_reasons": dict(self.denied_reasons.most_common(10)),
            "latency": {
                "avg_ms": round(avg, 2),
                "p50_ms": round(p50, 2),
                "p95_ms": round(p95, 2),
                "min_ms": round(min(self.latencies), 2) if self.latencies else 0.0,
                "max_ms": round(max(self.latencies), 2) if self.latencies else 0.0,
            },
            "anomalies": self.anomalies,
            "reconciliation": self.reconciliation,
        }


class AccessLogAnalyzer:
    """Parses access.log, computes security metrics, detects anomalies, and reconciles with audit chain."""

    def __init__(
        self,
        access_log_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None,
    ):
        self.access_log_path = access_log_path or Path("access.log")
        self.audit_log_path = audit_log_path or DEFAULT_AUDIT_LOG_PATH

    def analyze(self) -> LogAnalysisReport:
        report = LogAnalysisReport()
        if not self.access_log_path.exists():
            return report

        raw_entries = []
        with open(self.access_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    raw_entries.append(entry)
                except Exception:
                    pass

        tainted_sessions = set()
        client_consecutive_denials: Dict[str, int] = defaultdict(int)
        timestamps: List[datetime] = []

        for entry in raw_entries:
            # Lifecycle events (taint_set, taint_cleared, approval, hash_mismatch)
            ev = entry.get("event")
            if ev == "taint_set":
                sess = entry.get("session_id")
                if sess:
                    tainted_sessions.add(sess)
                continue
            elif ev == "taint_cleared":
                sess = entry.get("session_id")
                if sess in tainted_sessions:
                    tainted_sessions.remove(sess)
                continue

            # Standard request lines
            report.total_requests += 1
            tool = entry.get("tool") or "non_tool_endpoint"
            outcome = entry.get("outcome") or "unknown"
            client_id = entry.get("client_id") or "unknown"
            reason = entry.get("reason_code")
            latency = float(entry.get("latency_ms", 0.0))

            report.requests_per_tool[tool] += 1
            report.outcome_breakdown[outcome] += 1
            report.latencies.append(latency)

            # Denials tracking
            if outcome == "deny":
                report.top_denied_tools[tool] += 1
                if reason:
                    report.denied_reasons[reason] += 1
                client_consecutive_denials[client_id] += 1
                if client_consecutive_denials[client_id] >= 3:
                    report.anomalies.append({
                        "type": "repeated_denials",
                        "client_id": client_id,
                        "consecutive_count": client_consecutive_denials[client_id],
                        "last_tool": tool,
                        "reason": reason,
                    })
            else:
                client_consecutive_denials[client_id] = 0

            # Anomaly: Calls after taint
            sess = entry.get("session_id") or entry.get("task_id")
            if sess and sess in tainted_sessions and outcome not in ("hold", "deny"):
                report.anomalies.append({
                    "type": "unexpected_call_after_taint",
                    "session_id": sess,
                    "tool": tool,
                    "outcome": outcome,
                })

            # Timestamps for burst analysis
            ts_str = entry.get("ts")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(dt)
                except Exception:
                    pass

        # Anomaly: Bursts (> 15 requests in any 1-second rolling window)
        timestamps.sort()
        for i in range(len(timestamps)):
            window_end = timestamps[i].timestamp() + 1.0
            count = sum(1 for t in timestamps[i:] if t.timestamp() <= window_end)
            if count >= 15:
                report.anomalies.append({
                    "type": "traffic_burst",
                    "window_start": timestamps[i].isoformat(),
                    "requests_in_1s": count,
                })
                break

        # Reconcile access.log with audit_chain.jsonl
        report.reconciliation = self.reconcile()
        return report

    def backfill_audit_chain(self) -> int:
        """Backfills any historic access.log tool calls missing from the audit chain."""
        if not self.access_log_path.exists():
            return 0

        from mcp_shield.audit.chain import audit_manager

        # Gather existing audit request_ids
        existing_audit_ids = set()
        if self.audit_log_path.exists():
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            existing_audit_ids.add(json.loads(line).get("request_id"))
                        except Exception:
                            pass

        backfilled = 0
        with open(self.access_log_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    req_id = entry.get("request_id")
                    if req_id and req_id not in existing_audit_ids:
                        if entry.get("path") and "/mcp/proxy" in entry.get("path") and entry.get("tool"):
                            scores_dict = {}
                            if entry.get("scores") and isinstance(entry["scores"], dict):
                                scores_dict = {
                                    k: float(v) for k, v in entry["scores"].items()
                                    if isinstance(v, (int, float)) and k not in ("latency_ms", "checkpoint")
                                }
                            audit_manager.append(
                                request_id=req_id,
                                user_id=entry.get("user_id") or "usr_unknown",
                                client_id=entry.get("client_id") or "agent_unknown",
                                task_id=entry.get("task_id") or "",
                                server=entry.get("mcp_server") or "unknown",
                                tool=entry.get("tool"),
                                args_sha256=entry.get("args_sha256") or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                model_name="openjev-v1",
                                model_version="0.1.0",
                                scores=scores_dict,
                                outcome=entry.get("outcome") or "allow",
                                reason_code=entry.get("reason_code"),
                                latency_ms=float(entry.get("latency_ms", 1.0)),
                            )
                            existing_audit_ids.add(req_id)
                            backfilled += 1
                except Exception:
                    pass

        return backfilled

    def rebuild_audit_chain_from_access_log(self) -> int:
        """Completely reconstructs the cryptographic audit chain from access.log tool calls."""
        if self.audit_log_path.exists():
            self.audit_log_path.unlink()
        from mcp_shield.audit.chain import audit_manager
        audit_manager._sync_state()
        return self.backfill_audit_chain()

    def reconcile(self) -> Dict[str, Any]:
        """Reconciles access.log with audit_chain.jsonl ensuring bidirectional consistency."""
        access_req_ids = set()
        access_tool_req_ids = set()

        if self.access_log_path.exists():
            with open(self.access_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        req_id = e.get("request_id")
                        if req_id:
                            access_req_ids.add(req_id)
                            # Track tool calls made through proxy
                            if e.get("path") and "/mcp/proxy" in e.get("path") and e.get("tool"):
                                access_tool_req_ids.add(req_id)
                    except Exception:
                        pass

        audit_req_ids = set()
        if self.audit_log_path.exists():
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                        req_id = r.get("request_id")
                        if req_id:
                            audit_req_ids.add(req_id)
                    except Exception:
                        pass

        # Discrepancies
        audit_missing_in_access = audit_req_ids - access_req_ids
        tool_access_missing_in_audit = access_tool_req_ids - audit_req_ids

        is_reconciled = (len(audit_missing_in_access) == 0 and len(tool_access_missing_in_audit) == 0)

        return {
            "reconciled": is_reconciled,
            "total_access_log_requests": len(access_req_ids),
            "total_mcp_tool_access_requests": len(access_tool_req_ids),
            "total_audit_records": len(audit_req_ids),
            "matching_records": len(audit_req_ids.intersection(access_tool_req_ids)),
            "audit_missing_in_access_count": len(audit_missing_in_access),
            "access_missing_in_audit_count": len(tool_access_missing_in_audit),
        }
