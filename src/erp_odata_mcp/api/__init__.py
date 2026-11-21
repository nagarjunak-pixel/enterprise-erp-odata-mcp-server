"""FastAPI control plane for Enterprise ERP OData MCP Server (Port 8270)."""

from __future__ import annotations

from erp_odata_mcp.api.app import app, create_app

__all__ = ["app", "create_app"]
