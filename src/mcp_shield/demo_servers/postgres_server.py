"""Simulated Postgres MCP server for Streamable HTTP demo."""

import json
from typing import Any, Dict
from fastapi import FastAPI, Header, Request

postgres_mcp_app = FastAPI(title="Postgres MCP Server")

POSTGRES_TOOLS = [
    {
        "name": "query_readonly",
        "description": "Execute a read-only SQL query against Postgres database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "SELECT query to execute"},
            },
            "required": ["sql"],
        },
    },
    {
        "name": "execute_dml",
        "description": "Execute an INSERT/UPDATE/DELETE query against Postgres database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "DML statement to execute"},
            },
            "required": ["sql"],
        },
    },
]


@postgres_mcp_app.post("/mcp")
async def postgres_mcp_handler(request: Request, mcp_session_id: str = Header("session-pg-demo")):
    body = await request.body()
    payload = json.loads(body.decode("utf-8")) if body else {}
    req_id = payload.get("id")
    method = payload.get("method")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "postgres-demo-server", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": POSTGRES_TOOLS},
        }

    if method == "tools/call":
        params = payload.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "query_readonly":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps([{"id": 1, "status": "active", "rows": 10}])}],
                },
            }

        if name == "execute_dml":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": "Query executed: 1 row affected."}],
                },
            }

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}
