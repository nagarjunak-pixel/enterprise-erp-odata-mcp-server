"""Stdio JSON-RPC 2.0 Model Context Protocol (MCP) server for Enterprise ERP OData."""

from __future__ import annotations

from erp_odata_mcp.mcp.server import MCPServerSession, run_stdio_server

__all__ = ["MCPServerSession", "run_stdio_server"]
