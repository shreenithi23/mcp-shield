"""Access Logging Middleware for MCP Shield.

Guarantees that EVERY request reaching the gateway produces exactly one
structured JSON line in access.log, with zero token/secret leakage.
"""

import time
import uuid
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mcp_shield.logging import (
    AccessLogContext,
    current_log_context,
    record_access_log,
)


class AccessLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that intercepts every request and emits a structured access log line."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        client_ip = request.client.host if request.client else "unknown"

        ctx = AccessLogContext(
            request_id=request_id,
            remote_ip=client_ip,
            method=request.method,
            path=request.url.path,
            start_time=time.perf_counter(),
        )
        token = current_log_context.set(ctx)

        http_status = 500
        try:
            response = await call_next(request)
            http_status = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        except Exception as exc:
            ctx.outcome = "error"
            ctx.reason_code = type(exc).__name__
            http_status = 500
            raise
        finally:
            latency_ms = (time.perf_counter() - ctx.start_time) * 1000.0
            
            # Map HTTP status to default outcome if not explicitly set
            if ctx.outcome == "allow" and http_status >= 400:
                if http_status in (401, 403):
                    ctx.outcome = "deny"
                elif http_status >= 500:
                    ctx.outcome = "error"
                else:
                    ctx.outcome = "deny"

            record_access_log(
                ctx=ctx,
                http_status=http_status,
                latency_ms=latency_ms,
            )
            current_log_context.reset(token)
