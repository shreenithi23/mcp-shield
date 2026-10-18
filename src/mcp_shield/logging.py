"""Structured Audit and Access Logging for MCP Shield."""

import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field

from mcp_shield.config import settings

# Outcome types according to gateway specification
OutcomeType = Literal["allow", "allow_narrower", "hold", "deny", "error"]


class AccessLogEntry(BaseModel):
    """Schema for each JSON line in access.log."""
    ts: str = Field(description="ISO 8601 UTC timestamp")
    request_id: str = Field(description="Unique request ID")
    user_id: Optional[str] = Field(default=None)
    client_id: Optional[str] = Field(default=None)
    task_id: Optional[str] = Field(default=None)
    remote_ip: Optional[str] = Field(default=None)
    method: str
    path: str
    mcp_server: Optional[str] = Field(default=None)
    tool: Optional[str] = Field(default=None)
    token_jti: Optional[str] = Field(default=None)
    dpop_ok: Optional[bool] = Field(default=None)
    outcome: OutcomeType = Field(default="allow")
    reason_code: Optional[str] = Field(default=None)
    http_status: int
    upstream_status: Optional[int] = Field(default=None)
    args_sha256: Optional[str] = Field(default=None)
    scores: Optional[Dict[str, Any]] = Field(default=None)
    latency_ms: float

    def to_json_line(self) -> str:
        """Serializes entry to single JSON string with strict field ordering."""
        return json.dumps(self.model_dump(), separators=(",", ":"))


class AccessLogContext(BaseModel):
    """Context container updated during the request lifecycle."""
    request_id: str
    user_id: Optional[str] = None
    client_id: Optional[str] = None
    task_id: Optional[str] = None
    remote_ip: Optional[str] = None
    method: str = "GET"
    path: str = "/"
    mcp_server: Optional[str] = None
    tool: Optional[str] = None
    token_jti: Optional[str] = None
    dpop_ok: Optional[bool] = None
    outcome: OutcomeType = "allow"
    reason_code: Optional[str] = None
    http_status: int = 200
    upstream_status: Optional[int] = None
    args_sha256: Optional[str] = None
    scores: Optional[Dict[str, Any]] = None
    start_time: float = 0.0


# Request-scoped context variable
current_log_context: ContextVar[Optional[AccessLogContext]] = ContextVar(
    "current_log_context", default=None
)


def hash_arguments(args: Any) -> Optional[str]:
    """Computes SHA-256 hash of arguments. Never logs raw arguments."""
    if args is None:
        return None
    try:
        if isinstance(args, (dict, list)):
            serialized = json.dumps(args, sort_keys=True, separators=(",", ":"))
        elif isinstance(args, bytes):
            serialized = args.decode("utf-8", errors="replace")
        else:
            serialized = str(args)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except Exception:
        return None


class RawJsonFormatter(logging.Formatter):
    """Outputs raw message string without standard logging prefixes."""
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


_access_logger: Optional[logging.Logger] = None


def get_access_logger(log_file_path: Optional[str] = None) -> logging.Logger:
    """Returns singleton access logger with RotatingFileHandler."""
    global _access_logger
    target_path = log_file_path or settings.ACCESS_LOG_PATH
    
    if _access_logger is not None:
        return _access_logger

    logger = logging.getLogger("mcp_shield.access")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Avoid duplicate handlers
    if not logger.handlers:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            target_path,
            maxBytes=settings.ACCESS_LOG_MAX_BYTES,
            backupCount=settings.ACCESS_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(RawJsonFormatter())
        logger.addHandler(handler)

    _access_logger = logger
    return _access_logger


def reset_access_logger_for_test(new_path: str) -> logging.Logger:
    """Helper for unit tests to redirect logs to a temporary file."""
    global _access_logger
    logger = logging.getLogger("mcp_shield.access")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for h in list(logger.handlers):
        h.close()
        logger.removeHandler(h)
    
    Path(new_path).parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        new_path,
        maxBytes=settings.ACCESS_LOG_MAX_BYTES,
        backupCount=settings.ACCESS_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(RawJsonFormatter())
    logger.addHandler(handler)
    _access_logger = logger
    return logger


def record_access_log(
    ctx: AccessLogContext,
    http_status: int,
    latency_ms: float,
    outcome: Optional[OutcomeType] = None,
    reason_code: Optional[str] = None,
) -> AccessLogEntry:
    """Finalizes and writes an access log entry to access.log."""
    now_utc = datetime.now(timezone.utc).isoformat()
    entry = AccessLogEntry(
        ts=now_utc,
        request_id=ctx.request_id,
        user_id=ctx.user_id,
        client_id=ctx.client_id,
        task_id=ctx.task_id,
        remote_ip=ctx.remote_ip,
        method=ctx.method,
        path=ctx.path,
        mcp_server=ctx.mcp_server,
        tool=ctx.tool,
        token_jti=ctx.token_jti,
        dpop_ok=ctx.dpop_ok,
        outcome=outcome or ctx.outcome,
        reason_code=reason_code or ctx.reason_code,
        http_status=http_status,
        upstream_status=ctx.upstream_status,
        args_sha256=ctx.args_sha256,
        scores=ctx.scores,
        latency_ms=round(latency_ms, 3),
    )
    logger = get_access_logger()
    logger.info(entry.to_json_line())
    for handler in logger.handlers:
        handler.flush()

    # Automatically append to cryptographic hash-chained audit trail for MCP tool calls
    if entry.path and "/mcp/proxy" in entry.path and entry.tool:
        try:
            from mcp_shield.audit.chain import audit_manager
            scores_dict = {}
            model_name = "openjev-v1"
            model_version = "0.1.0"
            if entry.scores and isinstance(entry.scores, dict):
                model_name = entry.scores.get("model_name", "openjev-v1")
                model_version = entry.scores.get("model_version", "0.1.0")
                scores_dict = {
                    k: float(v) for k, v in entry.scores.items()
                    if isinstance(v, (int, float)) and k not in ("latency_ms", "checkpoint")
                }

            audit_manager.append(
                request_id=entry.request_id,
                user_id=entry.user_id or "usr_unknown",
                client_id=entry.client_id or "agent_unknown",
                task_id=entry.task_id or "",
                server=entry.mcp_server or "unknown",
                tool=entry.tool,
                args_sha256=entry.args_sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                model_name=model_name,
                model_version=model_version,
                scores=scores_dict,
                outcome=entry.outcome,
                reason_code=entry.reason_code,
                latency_ms=entry.latency_ms,
            )
        except Exception:
            pass

    return entry
