"""Stdio JSON-RPC 2.0 MCP server exposing schema-validated SAP S/4HANA OData v4 tools."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from erp_odata_mcp import __version__
from erp_odata_mcp.guardrails import ODataGuardrailGateway
from erp_odata_mcp.schema import get_entity_schema
from erp_odata_mcp.types import ODataQueryParams, PurchaseOrderReleaseRequest

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "odata_list_entities",
        "description": "List all released SAP S/4HANA Clean-Core OData v4 EntitySets and their module metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "odata_describe_schema",
        "description": "Return full EDM property schema, types, filterability, and PII flags for an OData EntitySet.",
        "inputSchema": {
            "type": "object",
            "properties": {"entity_set": {"type": "string"}},
            "required": ["entity_set"],
        },
    },
    {
        "name": "odata_validate_query",
        "description": "Validate OData v4 $select, $filter, $orderby, $expand, and $top against Clean-Core schema & C++20 security guardrails without executing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_set": {"type": "string"},
                "select": {"type": "array", "items": {"type": "string"}},
                "filter_expr": {"type": "string"},
                "orderby": {"type": "string"},
                "expand": {"type": "array", "items": {"type": "string"}},
                "top": {"type": "integer"},
                "skip": {"type": "integer"},
                "principal": {"type": "object"},
            },
            "required": ["entity_set"],
        },
    },
    {
        "name": "odata_query_entities",
        "description": "Execute a schema-validated, CompanyCode (BUKRS) isolated, PII-masked SAP S/4HANA OData v4 query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_set": {"type": "string"},
                "select": {"type": "array", "items": {"type": "string"}},
                "filter_expr": {"type": "string"},
                "orderby": {"type": "string"},
                "expand": {"type": "array", "items": {"type": "string"}},
                "top": {"type": "integer"},
                "skip": {"type": "integer"},
                "principal": {"type": "object"},
            },
            "required": ["entity_set"],
        },
    },
    {
        "name": "odata_simulate_po_release",
        "description": "Simulate SAP MM PurchaseOrder release gated by fresh human approval token (APR-...) and 3-way match verification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "purchase_order": {"type": "string"},
                "human_approval_token": {"type": "string"},
                "reason": {"type": "string"},
                "principal": {"type": "object"},
            },
            "required": ["purchase_order"],
        },
    },
    {
        "name": "odata_verify_audit_log",
        "description": "Verify cryptographic SHA-256 and C++20 SplitMix64 hash-chain integrity across all ERP tool calls.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServerSession:
    """Stateful MCP session backed by a governed `ODataGuardrailGateway`."""

    def __init__(self, gateway: ODataGuardrailGateway | None = None) -> None:
        self.gateway = gateway if gateway is not None else ODataGuardrailGateway()

    def _dispatch_tool(self, name: str, args: dict[str, Any]) -> Any:
        if name == "odata_list_entities":
            return [s.model_dump(mode="json") for s in self.gateway.list_schemas()]
        if name == "odata_describe_schema":
            ent = str(args.get("entity_set", ""))
            schema = get_entity_schema(ent)
            if schema is None:
                raise ValueError(f"Unknown EntitySet: {ent!r}")
            return schema.model_dump(mode="json")
        if name == "odata_validate_query":
            q = ODataQueryParams.model_validate(args)
            rep, _ = self.gateway.validate_query(q)
            return rep.model_dump(mode="json")
        if name == "odata_query_entities":
            q = ODataQueryParams.model_validate(args)
            return self.gateway.execute_query(q).model_dump(mode="json")
        if name == "odata_simulate_po_release":
            r = PurchaseOrderReleaseRequest.model_validate(args)
            return self.gateway.simulate_po_release(r).model_dump(mode="json")
        if name == "odata_verify_audit_log":
            return {
                "integrity": self.gateway.verify_audit_integrity(),
                "entries": [e.model_dump(mode="json") for e in self.gateway.get_audit_log()],
            }
        raise ValueError(f"Unknown MCP tool: {name!r}")

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        method = req.get("method", "")
        req_id = req.get("id")

        if method == "notifications/initialized" or req_id is None:
            return None
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "enterprise-erp-odata-mcp-server",
                        "version": __version__,
                    },
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
        if method == "tools/call":
            params = req.get("params") or {}
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments") or {})
            try:
                payload = self._dispatch_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def run_stdio_server(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Serve newline-delimited JSON-RPC 2.0 MCP requests over stdio."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    session = MCPServerSession()
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            out_stream.write(json.dumps(err) + "\n")
            out_stream.flush()
            continue
        resp = session.handle_request(req)
        if resp is not None:
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()
