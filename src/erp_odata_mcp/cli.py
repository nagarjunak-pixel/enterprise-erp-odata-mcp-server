"""Typer CLI entrypoint for Enterprise ERP OData MCP Server."""

from __future__ import annotations

import json

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from erp_odata_mcp.demo import run_demo_scenarios
from erp_odata_mcp.guardrails import ODataGuardrailGateway
from erp_odata_mcp.kernels import benchmark_kernels
from erp_odata_mcp.mcp import run_stdio_server
from erp_odata_mcp.schema import ENTITY_SCHEMAS, get_entity_schema
from erp_odata_mcp.types import AgentPrincipal, ODataQueryParams

app = typer.Typer(
    name="erp-odata-mcp",
    help="Enterprise ERP OData v4 & SAP S/4HANA Clean-Core MCP Server with C++20 Guardrails.",
    no_args_is_help=True,
)
console = Console()


@app.command("schema")
def schema_cmd(
    entity_set: str | None = typer.Argument(
        None, help="Optional EntitySet name (e.g. A_PurchaseOrder)"
    ),
) -> None:
    """Inspect Clean-Core SAP S/4HANA OData v4 EntitySet metadata."""
    if entity_set is None:
        typer.echo(
            json.dumps([s.model_dump(mode="json") for s in ENTITY_SCHEMAS.values()], indent=2)
        )
        return
    schema = get_entity_schema(entity_set)
    if schema is None:
        typer.echo(json.dumps({"error": f"Unknown EntitySet: {entity_set}"}))
        raise typer.Exit(code=1)
    typer.echo(json.dumps(schema.model_dump(mode="json"), indent=2))


@app.command("validate")
def validate_cmd(
    entity_set: str = typer.Argument(...),
    filter_expr: str | None = typer.Option(None, "--filter", "-f"),
    select: str | None = typer.Option(None, "--select", "-s"),
    top: int = typer.Option(50, "--top"),
) -> None:
    """Validate an OData v4 query against Clean-Core metadata and C++20 security rules."""
    gw = ODataGuardrailGateway()
    sel_list = [x.strip() for x in select.split(",") if x.strip()] if select else []
    rep, _ = gw.validate_query(
        ODataQueryParams(entity_set=entity_set, select=sel_list, filter_expr=filter_expr, top=top)
    )
    typer.echo(json.dumps(rep.model_dump(mode="json"), indent=2))
    if not rep.allowed:
        raise typer.Exit(code=1)


@app.command("query")
def query_cmd(
    entity_set: str = typer.Argument(...),
    filter_expr: str | None = typer.Option(None, "--filter", "-f"),
    select: str | None = typer.Option(None, "--select", "-s"),
    company_codes: str = typer.Option("1000", "--company-codes", "-c"),
    top: int = typer.Option(50, "--top"),
) -> None:
    """Execute a governed SAP S/4HANA OData v4 query with BUKRS isolation and PII masking."""
    gw = ODataGuardrailGateway()
    sel_list = [x.strip() for x in select.split(",") if x.strip()] if select else []
    codes = [c.strip() for c in company_codes.split(",") if c.strip()]
    res = gw.execute_query(
        ODataQueryParams(
            entity_set=entity_set,
            select=sel_list,
            filter_expr=filter_expr,
            top=top,
            principal=AgentPrincipal(allowed_company_codes=codes),
        )
    )
    typer.echo(json.dumps(res.model_dump(mode="json"), indent=2))
    if not res.allowed:
        raise typer.Exit(code=1)


@app.command("demo")
def demo_cmd(json_out: bool = typer.Option(False, "--json")) -> None:
    """Run 6 enterprise SAP S/4HANA OData guardrail scenarios + C++20 benchmark."""
    res = run_demo_scenarios()
    if json_out:
        typer.echo(json.dumps(res, indent=2))
        return

    tbl = Table(title="Enterprise ERP OData MCP Server — 6 Clean-Core Guardrail Scenarios")
    tbl.add_column("Scenario")
    tbl.add_column("Decision")
    tbl.add_column("Outcome / Guardrail Proof")

    for sc in res["scenarios"]:
        decision = (
            "[bold green]ALLOWED[/bold green]" if sc["allowed"] else "[bold red]BLOCKED[/bold red]"
        )
        if sc["allowed"] and "returned_rows" in sc:
            proof = (
                f"rows={sc['returned_rows']}, cross_bukrs_filtered={sc['denied_cross_company_rows']}, "
                f"masked={','.join(sc['redacted_fields'])}"
            )
        elif sc["allowed"]:
            proof = f"new_status={sc.get('new_status')}, audit_seq=#{sc.get('audit_seq')}"
        else:
            proof = ",".join(sc.get("violation_codes", []))
        tbl.add_row(sc["title"], decision, proof)

    console.print(tbl)
    bench = res["kernel_benchmark"]
    audit = res["audit_integrity"]
    console.print(
        f"Audit Chain Verified: valid={audit['valid']} ({audit['records_checked']} tool calls) | "
        f"C++20 Kernel Benchmark ({bench['num_rows']} rows, {bench['audit_records']} audit links): "
        f"C++20={bench['native_ms']} ms vs Python={bench['python_ms']} ms ({bench['speedup_x']}x speedup)"
    )


@app.command("bench")
def bench_cmd(
    rows: int = typer.Option(20000, "--rows"),
    audit_len: int = typer.Option(25000, "--audit-len"),
) -> None:
    """Benchmark C++20 OData $filter scanner, BUKRS row filter & SplitMix64 audit verifier."""
    typer.echo(json.dumps(benchmark_kernels(num_rows=rows, audit_len=audit_len), indent=2))


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8270, "--port"),
) -> None:
    """Start the FastAPI control plane on port 8270."""
    uvicorn.run("erp_odata_mcp.api.app:app", host=host, port=port)  # pragma: no cover


@app.command("mcp")
def mcp_cmd() -> None:
    """Start the stdio JSON-RPC 2.0 Model Context Protocol (MCP) server."""
    run_stdio_server()
