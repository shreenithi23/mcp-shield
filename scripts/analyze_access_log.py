#!/usr/bin/env python3
"""Script to analyze access.log, report statistics, anomalies, and reconcile with the audit chain."""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mcp_shield.audit.analyzer import AccessLogAnalyzer
from mcp_shield.audit.chain import audit_manager

# ANSI Colors
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="MCP Shield access.log profiler & audit reconciler")
    parser.add_argument("--access-log", default=str(PROJECT_ROOT / "access.log"), help="Path to access.log")
    parser.add_argument("--audit-log", default=str(PROJECT_ROOT / "audit_chain.jsonl"), help="Path to audit_chain.jsonl")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text report")
    parser.add_argument("--sync", action="store_true", help="Backfill any historic access.log tool calls into audit chain")
    parser.add_argument("--rebuild-chain", action="store_true", help="Reconstruct cryptographic audit chain from access.log from scratch")
    parser.add_argument("--export-siem", help="Optional path to export SIEM ECS JSON records")
    args = parser.parse_args()

    analyzer = AccessLogAnalyzer(
        access_log_path=Path(args.access_log),
        audit_log_path=Path(args.audit_log),
    )
    if args.rebuild_chain:
        count = analyzer.rebuild_audit_chain_from_access_log()
        print(f"{GREEN}Reconstructed cryptographic audit chain with {count} records from access.log.{RESET}")
    elif args.sync:
        backfilled = analyzer.backfill_audit_chain()
        if backfilled > 0:
            print(f"{GREEN}Synchronized {backfilled} historical access.log records into audit chain.{RESET}")

    report = analyzer.analyze()
    data = report.to_dict()

    if args.export_siem:
        audit_manager.export_siem(output_path=Path(args.export_siem))
        print(f"SIEM export written to {args.export_siem}")

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}   📊  MCP SHIELD — ACCESS LOG PROFILE & AUDIT CHAIN RECONCILIATION   {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")

    print(f"{BOLD}Total Gateway Requests Processed:{RESET} {data['total_requests']}")

    # Outcomes
    print(f"\n{BOLD}Outcome Breakdown:{RESET}")
    for outcome, cnt in data["outcome_breakdown"].items():
        color = GREEN if outcome in ("allow", "allow_narrower") else (YELLOW if outcome == "hold" else RED)
        pct = (cnt / data["total_requests"] * 100) if data["total_requests"] > 0 else 0
        print(f"  - {color}{outcome:<16}{RESET}: {cnt:>5} ({pct:>5.1f}%)")

    # Latencies
    lat = data["latency"]
    print(f"\n{BOLD}Latency Metrics (ms):{RESET}")
    print(f"  - Avg: {lat['avg_ms']} ms | p50: {lat['p50_ms']} ms | p95: {lat['p95_ms']} ms (Min: {lat['min_ms']}, Max: {lat['max_ms']})")

    # Top Tools
    print(f"\n{BOLD}Top Requested Tools:{RESET}")
    for tool, cnt in list(data["requests_per_tool"].items())[:8]:
        print(f"  - {tool:<28}: {cnt:>4} calls")

    # Top Denied Tools & Reasons
    if data["top_denied_tools"]:
        print(f"\n{BOLD}{RED}Top Denied Tools:{RESET}")
        for tool, cnt in data["top_denied_tools"].items():
            print(f"  - {tool:<28}: {cnt} denials")

    if data["top_denial_reasons"]:
        print(f"\n{BOLD}{RED}Top Denial Reasons:{RESET}")
        for rsn, cnt in data["top_denial_reasons"].items():
            print(f"  - {rsn:<32}: {cnt}")

    # Anomalies
    print(f"\n{BOLD}Security Anomalies Detected:{RESET} {len(data['anomalies'])}")
    if data["anomalies"]:
        for anom in data["anomalies"][:5]:
            print(f"  ⚠️  {YELLOW}{anom.get('type')}{RESET}: {anom}")
    else:
        print(f"  {GREEN}✅ No traffic bursts, repeated denials, or unauthorized calls post-taint detected.{RESET}")

    # Cryptographic Chain Verification
    valid_chain, count, err = audit_manager.verify_chain()
    print(f"\n{BOLD}Cryptographic Hash Chain Verification:{RESET}")
    if valid_chain:
        print(f"  {GREEN}✅ Chain Integrity VERIFIED: {count} immutable records valid (Genesis -> Head).{RESET}")
    else:
        print(f"  {RED}❌ Chain Integrity BROKEN at {count} records: {err}{RESET}")

    # Reconciliation
    rec = data["reconciliation"]
    print(f"\n{BOLD}Audit Log Reconciliation:{RESET}")
    print(f"  - access.log MCP Tool Requests : {rec['total_mcp_tool_access_requests']}")
    print(f"  - audit_chain.jsonl Records   : {rec['total_audit_records']}")
    print(f"  - Bidirectional Matching Keys : {rec['matching_records']}")

    if rec["reconciled"]:
        print(f"  {GREEN}✅ 100% RECONCILED: Every audit record matches access.log and vice-versa.{RESET}\n")
    else:
        print(f"  {YELLOW}⚠️  Reconciliation delta: {rec['audit_missing_in_access_count']} missing in access, {rec['access_missing_in_audit_count']} missing in audit.{RESET}\n")


if __name__ == "__main__":
    main()
