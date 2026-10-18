"""Deterministic in-process Stub MCP Server for unit and integration testing."""

import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

EXPECTED_STUB_PAT = "stub_upstream_pat_secret_9999"


async def stub_mcp_app(scope, receive, send):
    """ASGI application simulating an upstream Streamable HTTP MCP server."""
    request = Request(scope, receive)
    
    if request.method != "POST":
        response = Response(status_code=405)
        await response(scope, receive, send)
        return

    auth_header = request.headers.get("authorization", "")
    session_id = request.headers.get("mcp-session-id", "stub-session-001")

    # Fail if upstream PAT was not injected properly
    if not auth_header.startswith("Bearer "):
        response = JSONResponse(
            {"error": "unauthorized", "message": "Missing upstream Bearer credential"},
            status_code=401,
        )
        await response(scope, receive, send)
        return

    raw_body = await request.body()
    try:
        body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        body = {}

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params", {})

    headers = {"mcp-session-id": session_id, "content-type": "application/json"}

    # 1. Initialize
    if method == "initialize":
        data = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub-mcp-server", "version": "1.0.0"},
            },
        }
        response = JSONResponse(data, status_code=200, headers=headers)
        await response(scope, receive, send)
        return

    # 2. Notifications/initialized
    if method == "notifications/initialized":
        response = Response(status_code=202, headers=headers)
        await response(scope, receive, send)
        return

    # 3. Tools/list
    if method == "tools/list":
        data = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "list_issues",
                        "description": "List issues in repository",
                        "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}},
                    },
                    {
                        "name": "issue_read",
                        "description": "Read issue details",
                        "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "issue_number": {"type": "integer"}}},
                    },
                ]
            },
        }
        response = JSONResponse(data, status_code=200, headers=headers)
        await response(scope, receive, send)
        return

    # 4. Tools/call
    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        # Simulate Upstream 429
        if args.get("repo") == "simulate-rate-limit":
            response = JSONResponse(
                {"error": "rate limit exceeded"},
                status_code=429,
                headers=headers,
            )
            await response(scope, receive, send)
            return

        # Simulate Upstream 403
        if args.get("owner") == "forbidden-org":
            response = JSONResponse(
                {"error": "forbidden"},
                status_code=403,
                headers=headers,
            )
            await response(scope, receive, send)
            return

        if tool_name == "list_issues":
            data = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps([
                                {"number": 1, "title": "Zero-trust verification issue", "state": "open"},
                                {"number": 2, "title": "Second mock issue", "state": "closed"},
                            ]),
                        }
                    ]
                },
            }
            response = JSONResponse(data, status_code=200, headers=headers)
            await response(scope, receive, send)
            return

    # Fallback response
    data = {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"status": "ok", "method": method},
    }
    response = JSONResponse(data, status_code=200, headers=headers)
    await response(scope, receive, send)
