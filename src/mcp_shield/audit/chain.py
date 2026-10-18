"""Cryptographic Append-Only Hash-Chained Audit Trail and SIEM Exporter."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from mcp_shield.config import settings


GENESIS_HASH = "0" * 64
DEFAULT_AUDIT_LOG_PATH = Path(__file__).resolve().parents[3] / "audit_chain.jsonl"


class AuditRecord(BaseModel):
    """Schema for a single cryptographically hash-chained audit record."""
    index: int
    ts: str  # ISO 8601 UTC timestamp
    request_id: str
    user_id: str
    client_id: str
    task_id: str
    server: str
    tool: str
    args_sha256: str
    policy_version: str = "v1.2"
    model_name: str
    model_version: str
    scores: Dict[str, float]
    outcome: str  # allow, allow_narrower, hold, deny, error
    reason_code: Optional[str] = None
    latency_ms: float
    prev_hash: str
    record_hash: str

    def canonical_payload(self) -> str:
        """Returns deterministic JSON string of payload fields excluding record_hash."""
        data = {
            "index": self.index,
            "ts": self.ts,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "task_id": self.task_id,
            "server": self.server,
            "tool": self.tool,
            "args_sha256": self.args_sha256,
            "policy_version": self.policy_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "scores": self.scores,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "latency_ms": round(self.latency_ms, 2),
            "prev_hash": self.prev_hash,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


class AuditTrailManager:
    """Manages append-only, tamper-evident hash-chained audit records."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or DEFAULT_AUDIT_LOG_PATH
        self._last_hash = GENESIS_HASH
        self._last_index = -1
        self._sync_state()

    def _sync_state(self) -> None:
        """Reads existing chain from disk to resume latest index and hash."""
        if not self.log_path.exists():
            self._last_hash = GENESIS_HASH
            self._last_index = -1
            return

        last_valid_hash = GENESIS_HASH
        last_idx = -1
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec_dict = json.loads(line)
                    last_valid_hash = rec_dict.get("record_hash", GENESIS_HASH)
                    last_idx = rec_dict.get("index", last_idx)
        except Exception:
            pass

        self._last_hash = last_valid_hash
        self._last_index = last_idx

    @staticmethod
    def compute_hash(prev_hash: str, canonical_payload: str) -> str:
        """Computes SHA-256(prev_hash + canonical_payload)."""
        combined = f"{prev_hash}:{canonical_payload}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    def append(
        self,
        request_id: str,
        user_id: str,
        client_id: str,
        task_id: str,
        server: str,
        tool: str,
        args_sha256: str,
        model_name: str,
        model_version: str,
        scores: Dict[str, float],
        outcome: str,
        latency_ms: float,
        reason_code: Optional[str] = None,
        policy_version: str = "v1.2",
    ) -> AuditRecord:
        """Creates and appends an immutable hash-chained audit record."""
        now_utc = datetime.now(timezone.utc).isoformat()
        new_index = self._last_index + 1
        prev_hash = self._last_hash

        record = AuditRecord(
            index=new_index,
            ts=now_utc,
            request_id=request_id,
            user_id=user_id,
            client_id=client_id,
            task_id=task_id,
            server=server,
            tool=tool,
            args_sha256=args_sha256,
            policy_version=policy_version,
            model_name=model_name,
            model_version=model_version,
            scores=scores,
            outcome=outcome,
            reason_code=reason_code,
            latency_ms=latency_ms,
            prev_hash=prev_hash,
            record_hash="",
        )

        canonical = record.canonical_payload()
        rec_hash = self.compute_hash(prev_hash, canonical)
        record.record_hash = rec_hash

        # Atomic append to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.model_dump(), separators=(",", ":")) + "\n")

        self._last_hash = rec_hash
        self._last_index = new_index
        return record

    def verify_chain(self) -> Tuple[bool, int, Optional[str]]:
        """Verifies integrity of the entire cryptographic hash chain.
        
        Returns:
            (is_valid: bool, records_verified: int, error_message: Optional[str])
        """
        if not self.log_path.exists():
            return True, 0, None

        expected_prev_hash = GENESIS_HASH
        count = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    rec = AuditRecord(**data)
                except Exception as exc:
                    return False, count, f"Line {line_no}: Malformed JSON record - {str(exc)}"

                # 1. Verify index continuity
                if rec.index != count:
                    return False, count, f"Line {line_no}: Index mismatch (expected {count}, got {rec.index})"

                # 2. Verify prev_hash pointer
                if rec.prev_hash != expected_prev_hash:
                    return (
                        False,
                        count,
                        f"Line {line_no} (index {rec.index}): Chain broken! Expected prev_hash {expected_prev_hash[:16]}..., got {rec.prev_hash[:16]}...",
                    )

                # 3. Recompute and verify record_hash
                canonical = rec.canonical_payload()
                expected_hash = self.compute_hash(rec.prev_hash, canonical)
                if rec.record_hash != expected_hash:
                    return (
                        False,
                        count,
                        f"Line {line_no} (index {rec.index}): Tampering detected! Hash mismatch. Computed {expected_hash[:16]}..., stored {rec.record_hash[:16]}...",
                    )

                expected_prev_hash = rec.record_hash
                count += 1

        return True, count, None

    def export_siem(self, output_path: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Exports audit records formatted for standard SIEM ingestion (CEF/ECS-compatible)."""
        records = []
        if not self.log_path.exists():
            return records

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    # Convert to Elastic Common Schema (ECS) standard
                    ecs_event = {
                        "@timestamp": rec.get("ts"),
                        "event": {
                            "id": rec.get("request_id"),
                            "action": f"mcp_tool_{rec.get('outcome')}",
                            "outcome": "success" if rec.get("outcome") in ("allow", "allow_narrower") else "failure",
                            "category": ["access", "configuration"],
                            "type": ["info"],
                            "duration": int(rec.get("latency_ms", 0) * 1_000_000),  # nanoseconds
                        },
                        "user": {"id": rec.get("user_id")},
                        "client": {"id": rec.get("client_id")},
                        "mcp": {
                            "server": rec.get("server"),
                            "tool": rec.get("tool"),
                            "args_sha256": rec.get("args_sha256"),
                            "policy_version": rec.get("policy_version"),
                            "reason_code": rec.get("reason_code"),
                        },
                        "ai": {
                            "model_name": rec.get("model_name"),
                            "model_version": rec.get("model_version"),
                            "scores": rec.get("scores"),
                        },
                        "chain": {
                            "index": rec.get("index"),
                            "prev_hash": rec.get("prev_hash"),
                            "record_hash": rec.get("record_hash"),
                        },
                    }
                    records.append(ecs_event)
                except Exception:
                    pass

        if output_path:
            with open(output_path, "w", encoding="utf-8") as out:
                json.dump(records, out, indent=2)

        return records


audit_manager = AuditTrailManager()
