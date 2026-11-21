"""FastAPI endpoints for governed SAP S/4HANA OData v4 querying, validation, and audit proof."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from erp_odata_mcp import __version__
from erp_odata_mcp.demo import run_demo_scenarios
from erp_odata_mcp.guardrails import ODataGuardrailGateway
from erp_odata_mcp.kernels import backend_name, benchmark_kernels
from erp_odata_mcp.schema import get_entity_schema
from erp_odata_mcp.types import (
    AuditEntry,
    EntitySetSchema,
    ODataQueryParams,
    ODataQueryResponse,
    PurchaseOrderReleaseRequest,
    PurchaseOrderReleaseResponse,
    QueryValidationReport,
)


def create_app(gateway: ODataGuardrailGateway | None = None) -> FastAPI:
    gw = gateway if gateway is not None else ODataGuardrailGateway()
    api = FastAPI(
        title="Enterprise ERP OData MCP Server",
        version=__version__,
        description="SAP S/4HANA Clean-Core OData v4 MCP Server with Schema Validation & C++20 Guardrails",
    )
    api.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @api.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "enterprise-erp-odata-mcp-server",
            "version": __version__,
            "backend": backend_name(),
        }

    @api.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        log = gw.get_audit_log()
        allowed_cnt = sum(1 for e in log if e.allowed)
        blocked_cnt = len(log) - allowed_cnt
        lines = [
            "# HELP erp_odata_calls_total Total ERP OData MCP calls audited",
            "# TYPE erp_odata_calls_total counter",
            f"erp_odata_calls_total {len(log)}",
            "# HELP erp_odata_calls_allowed_total Total allowed ERP OData calls",
            "# TYPE erp_odata_calls_allowed_total counter",
            f"erp_odata_calls_allowed_total {allowed_cnt}",
            "# HELP erp_odata_calls_blocked_total Total guardrail-blocked ERP OData calls",
            "# TYPE erp_odata_calls_blocked_total counter",
            f"erp_odata_calls_blocked_total {blocked_cnt}",
        ]
        return "\n".join(lines) + "\n"

    @api.get("/api/v1/entities", response_model=list[EntitySetSchema])
    def list_entities() -> list[EntitySetSchema]:
        return gw.list_schemas()

    @api.get("/api/v1/entities/{entity_set}", response_model=EntitySetSchema)
    def get_entity(entity_set: str) -> EntitySetSchema:
        schema = get_entity_schema(entity_set)
        if schema is None:
            raise HTTPException(status_code=404, detail=f"Unknown EntitySet: {entity_set}")
        return schema

    @api.post("/api/v1/validate", response_model=QueryValidationReport)
    def validate_query_ep(req: ODataQueryParams) -> QueryValidationReport:
        report, _ = gw.validate_query(req)
        return report

    @api.post("/api/v1/query", response_model=ODataQueryResponse)
    def execute_query_ep(req: ODataQueryParams) -> ODataQueryResponse:
        return gw.execute_query(req)

    @api.post("/api/v1/simulate-release", response_model=PurchaseOrderReleaseResponse)
    def simulate_release_ep(req: PurchaseOrderReleaseRequest) -> PurchaseOrderReleaseResponse:
        return gw.simulate_po_release(req)

    @api.get("/api/v1/audit", response_model=list[AuditEntry])
    def audit_log_ep() -> list[AuditEntry]:
        return gw.get_audit_log()

    @api.get("/api/v1/audit/verify")
    def verify_audit_ep() -> dict[str, Any]:
        return gw.verify_audit_integrity()

    @api.get("/api/v1/demo")
    def demo_ep() -> dict[str, Any]:
        return run_demo_scenarios()

    @api.get("/api/v1/bench")
    def bench_ep(num_rows: int = 20000, audit_len: int = 25000) -> dict[str, float | int | str]:
        return benchmark_kernels(num_rows=num_rows, audit_len=audit_len)

    return api


app = create_app()
