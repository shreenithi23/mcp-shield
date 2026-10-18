"""Simulated Slack MCP server for Streamable HTTP demo."""

import json
from typing import Any, Dict
from fastapi import FastAPI, Header, Request, Response

slack_mcp_app = FastAPI(title="Slack MCP Server")

SLACK_TOOLS = [
    {
        "name": "slack_post_message",
        "description": "Post a message to a Slack channel",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Target Slack channel (e.g. #security-alerts)"},
                "text": {"type": "string", "description": "Message text"},
            },
            "required": ["channel", "text"],
        },
    },
    {
        "name": "slack_read_channel",
        "description": "Read messages from a Slack channel",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Target channel name"},
            },
            "required": ["channel"],
        },
    },
]


@slack_mcp_app.post("/mcp")
async def slack_mcp_handler(request: Request, mcp_session_id: str = Header("session-slack-demo")):
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
                "serverInfo": {"name": "slack-demo-server", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": SLACK_TOOLS},
        }

    if method == "tools/call":
        params = payload.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "slack_post_message":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Message posted successfully to {args.get('channel')}: {args.get('text')}"}],
                    "status": "ok",
                },
            }

        if name == "slack_read_channel":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Channel {args.get('channel')} has 3 recent messages."}],
                },
            }

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}
