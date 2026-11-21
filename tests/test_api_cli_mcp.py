"""End-to-end tests for FastAPI REST endpoints, Typer CLI commands, and stdio MCP server."""

from __future__ import annotations

import io
import json

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from erp_odata_mcp.api import create_app
from erp_odata_mcp.cli import app as cli_app
from erp_odata_mcp.mcp import MCPServerSession, run_stdio_server

runner = CliRunner()


def test_fastapi_endpoints_and_metrics() -> None:
    client = TestClient(create_app())

    assert client.get("/health").status_code == 200
    ents = client.get("/api/v1/entities")
    assert ents.status_code == 200 and len(ents.json()) == 4

    assert client.get("/api/v1/entities/A_PurchaseOrder").status_code == 200
    assert client.get("/api/v1/entities/NO_SUCH_ENTITY").status_code == 404

    val = client.post(
        "/api/v1/validate",
        json={"entity_set": "A_PurchaseOrder", "filter_expr": "GrossAmount ge 1000"},
    )
    assert val.status_code == 200 and val.json()["allowed"] is True

    qry_ok = client.post(
        "/api/v1/query",
        json={"entity_set": "A_PurchaseOrder", "filter_expr": "GrossAmount ge 1000"},
    )
    assert qry_ok.status_code == 200 and qry_ok.json()["allowed"] is True

    qry_bad = client.post(
        "/api/v1/query",
        json={"entity_set": "A_PurchaseOrder", "filter_expr": "ZZ_FAKE eq '1'"},
    )
    assert qry_bad.status_code == 200 and qry_bad.json()["allowed"] is False

    rel = client.post(
        "/api/v1/simulate-release",
        json={"purchase_order": "4500010901", "human_approval_token": "APR-2026-DXB-1001"},
    )
    assert rel.status_code == 200 and rel.json()["allowed"] is True

    audit = client.get("/api/v1/audit")
    assert audit.status_code == 200 and len(audit.json()) == 3

    ver = client.get("/api/v1/audit/verify")
    assert ver.status_code == 200 and ver.json()["valid"] is True

    demo = client.get("/api/v1/demo")
    assert demo.status_code == 200 and len(demo.json()["scenarios"]) == 6

    bench = client.get("/api/v1/bench?num_rows=500&audit_len=500")
    assert bench.status_code == 200 and bench.json()["num_rows"] == 500

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "erp_odata_calls_allowed_total 2" in metrics.text
    assert "erp_odata_calls_blocked_total 1" in metrics.text


def test_typer_cli_commands() -> None:
    assert runner.invoke(cli_app, ["schema"]).exit_code == 0
    assert runner.invoke(cli_app, ["schema", "A_SalesOrder"]).exit_code == 0
    assert runner.invoke(cli_app, ["schema", "MISSING"]).exit_code == 1

    assert (
        runner.invoke(
            cli_app,
            ["validate", "A_PurchaseOrder", "-f", "GrossAmount ge 100", "-s", "PurchaseOrder"],
        ).exit_code
        == 0
    )
    assert runner.invoke(cli_app, ["validate", "A_PurchaseOrder", "-f", "1 eq 1"]).exit_code == 1

    assert (
        runner.invoke(
            cli_app,
            [
                "query",
                "A_PurchaseOrder",
                "-f",
                "GrossAmount ge 100",
                "-s",
                "PurchaseOrder",
                "-c",
                "1000,2000",
            ],
        ).exit_code
        == 0
    )
    assert runner.invoke(cli_app, ["query", "BSEG"]).exit_code == 1

    assert runner.invoke(cli_app, ["demo"]).exit_code == 0
    assert runner.invoke(cli_app, ["demo", "--json"]).exit_code == 0
    assert runner.invoke(cli_app, ["bench", "--rows", "400", "--audit-len", "400"]).exit_code == 0

    r_mcp = runner.invoke(
        cli_app, ["mcp"], input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n"
    )
    assert r_mcp.exit_code == 0
    assert '"id": 1' in r_mcp.stdout


def test_mcp_jsonrpc_session_and_stdio() -> None:
    session = MCPServerSession()
    assert session.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    init_r = session.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert (
        init_r is not None
        and init_r["result"]["serverInfo"]["name"] == "enterprise-erp-odata-mcp-server"
    )

    list_r = session.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert list_r is not None and len(list_r["result"]["tools"]) == 6

    tool_calls: list[tuple[str, dict[str, object]]] = [
        ("odata_list_entities", {}),
        ("odata_describe_schema", {"entity_set": "A_PurchaseOrder"}),
        (
            "odata_validate_query",
            {"entity_set": "A_PurchaseOrder", "filter_expr": "GrossAmount gt 10"},
        ),
        ("odata_query_entities", {"entity_set": "A_MaterialStock"}),
        (
            "odata_simulate_po_release",
            {"purchase_order": "4500010901", "human_approval_token": "APR-2026-MCP-01"},
        ),
        ("odata_verify_audit_log", {}),
    ]
    for idx, (tname, targs) in enumerate(tool_calls, start=10):
        resp = session.handle_request(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": tname, "arguments": targs},
            }
        )
        assert resp is not None and resp["result"]["isError"] is False

    err_schema = session.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {"name": "odata_describe_schema", "arguments": {"entity_set": "BAD"}},
        }
    )
    assert err_schema is not None and err_schema["result"]["isError"] is True

    err_unknown = session.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {"name": "bad_tool", "arguments": {}},
        }
    )
    assert err_unknown is not None and err_unknown["result"]["isError"] is True

    nf = session.handle_request({"jsonrpc": "2.0", "id": 52, "method": "unknown/method"})
    assert nf is not None and nf["error"]["code"] == -32601

    raw_in = io.StringIO(
        "\nnot-json\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})
        + "\n"
    )
    raw_out = io.StringIO()
    run_stdio_server(stdin=raw_in, stdout=raw_out)
    out_lines = [json.loads(x) for x in raw_out.getvalue().strip().splitlines()]
    assert len(out_lines) == 2 and out_lines[0]["error"]["code"] == -32700
