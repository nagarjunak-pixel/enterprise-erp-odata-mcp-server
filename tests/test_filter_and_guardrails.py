"""Tests for OData v4 `$filter` AST parser, Clean-Core schema checks, and tool-calling guardrails."""

from __future__ import annotations

import pytest

from erp_odata_mcp.guardrails import (
    FilterParseError,
    FilterTypeMismatchError,
    ODataGuardrailGateway,
    UnfilterableFieldError,
    UnknownFilterFieldError,
    evaluate_filter_ast,
    parse_odata_filter,
)
from erp_odata_mcp.schema import ENTITY_SCHEMAS
from erp_odata_mcp.types import (
    AgentPrincipal,
    ODataQueryParams,
    PurchaseOrderReleaseRequest,
)


def test_odata_filter_parser_functions_operators_and_errors() -> None:
    po_schema = ENTITY_SCHEMAS["A_PurchaseOrder"]
    je_schema = ENTITY_SCHEMAS["A_JournalEntryItem"]

    ast1 = parse_odata_filter(
        "(startswith(Supplier, 'VEND-') or endswith(Supplier, '01') or contains(Supplier, 'FUTTAIM')) "
        "and not (IsBlocked eq true) and GrossAmount gt 100 and GrossAmount le 500000 "
        "and Currency ne 'USD' and GrossAmount lt 999999",
        po_schema,
    )
    row = {
        "Supplier": "VEND-ALFUTTAIM-01",
        "IsBlocked": False,
        "GrossAmount": 148500.0,
        "Currency": "AED",
    }
    assert evaluate_filter_ast(ast1, row) is True

    ast_je = parse_odata_filter(
        "FiscalYear eq 2026 and AmountInCompanyCodeCurrency ge -90000", je_schema
    )
    assert (
        evaluate_filter_ast(ast_je, {"FiscalYear": 2026, "AmountInCompanyCodeCurrency": -64000.0})
        is True
    )

    # Escaped single quote inside OData string literal
    ast_q = parse_odata_filter("Supplier eq 'O''Reilly'", po_schema)
    assert evaluate_filter_ast(ast_q, {"Supplier": "O'Reilly"}) is True

    with pytest.raises(FilterParseError, match="Empty"):
        parse_odata_filter("   ", po_schema)
    with pytest.raises(FilterParseError, match="Unclosed"):
        parse_odata_filter("Supplier eq 'abc", po_schema)
    with pytest.raises(FilterParseError, match="Malformed numeric"):
        parse_odata_filter("GrossAmount eq 12.34.56", po_schema)
    with pytest.raises(FilterParseError, match="Unexpected character"):
        parse_odata_filter("GrossAmount @ 10", po_schema)
    with pytest.raises(FilterParseError, match="trailing token"):
        parse_odata_filter("IsBlocked eq false extra", po_schema)
    with pytest.raises(FilterParseError, match="Expected predicate"):
        parse_odata_filter("not", po_schema)
    with pytest.raises(FilterParseError, match="Unexpected end"):
        parse_odata_filter("(IsBlocked eq false", po_schema)
    with pytest.raises(FilterParseError, match="Expected '\\)'"):
        parse_odata_filter("(IsBlocked eq false extra)", po_schema)
    with pytest.raises(FilterParseError, match="Expected '\\(' after startswith"):
        parse_odata_filter("startswith Supplier", po_schema)
    with pytest.raises(FilterParseError, match="Expected field identifier"):
        parse_odata_filter("startswith('bad', 'x')", po_schema)
    with pytest.raises(FilterParseError, match="Expected ','"):
        parse_odata_filter("startswith(Supplier 'x')", po_schema)
    with pytest.raises(FilterParseError, match="Expected '\\)' after startswith"):
        parse_odata_filter("startswith(Supplier, 'x' extra)", po_schema)
    with pytest.raises(FilterParseError, match="comparison operator"):
        parse_odata_filter("Supplier and 'x'", po_schema)
    with pytest.raises(FilterParseError, match="Expected literal"):
        parse_odata_filter("Supplier eq (", po_schema)
    with pytest.raises(FilterParseError, match="Invalid \\$filter token"):
        parse_odata_filter("123 eq 123", po_schema)

    with pytest.raises(UnknownFilterFieldError):
        parse_odata_filter("ZZ_FAKE eq '1'", po_schema)
    with pytest.raises(UnfilterableFieldError):
        parse_odata_filter("VendorIBAN eq 'AE123'", po_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("Supplier eq 100", po_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("IsBlocked eq 'yes'", po_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("FiscalYear eq 2026.5", je_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("GrossAmount eq 'high'", po_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("startswith(GrossAmount, '1')", po_schema)
    with pytest.raises(FilterTypeMismatchError):
        parse_odata_filter("startswith(Supplier, 123)", po_schema)


def test_gateway_guardrails_pii_clearance_and_tamper_detection() -> None:
    gw = ODataGuardrailGateway()

    # Unknown entity set
    r_unk = gw.execute_query(ODataQueryParams(entity_set="BSEG_RAW_TABLE"))
    assert r_unk.allowed is False
    assert r_unk.validation.violations[0].code == "UNKNOWN_ENTITY_SET"

    # Negative pagination, top exceeded, expand disallowed, bad orderby, PII orderby, empty company codes
    r_multi = gw.execute_query(
        ODataQueryParams(
            entity_set="A_PurchaseOrder",
            select=["ZZ_BAD"],
            expand=["to_SecretVault"],
            orderby="VendorIBAN desc",
            top=999,
            filter_expr="((GrossAmount gt 1))",
            principal=AgentPrincipal(allowed_company_codes=[], max_cost_budget=5),
        )
    )
    assert r_multi.allowed is False
    codes = {v.code for v in r_multi.validation.violations}
    assert {
        "TOP_LIMIT_EXCEEDED",
        "UNKNOWN_SELECT_FIELD",
        "DISALLOWED_EXPAND",
        "UNKNOWN_ORDERBY_FIELD",
        "UNAUTHORIZED_COMPANY_CODE",
        "QUERY_COST_EXCEEDED",
    } <= codes

    r_neg = gw.execute_query(ODataQueryParams(entity_set="A_PurchaseOrder", top=-1))
    assert r_neg.validation.violations[0].code == "NEGATIVE_PAGINATION"

    r_ob_bad = gw.execute_query(
        ODataQueryParams(entity_set="A_PurchaseOrder", orderby="BadField side")
    )
    assert r_ob_bad.validation.violations[0].code == "UNKNOWN_ORDERBY_FIELD"

    r_unfilt = gw.execute_query(
        ODataQueryParams(entity_set="A_PurchaseOrder", filter_expr="VendorIBAN eq 'AE00'")
    )
    assert r_unfilt.validation.violations[0].code == "UNFILTERABLE_FIELD"

    r_typem = gw.execute_query(
        ODataQueryParams(entity_set="A_PurchaseOrder", filter_expr="GrossAmount eq 'abc'")
    )
    assert r_typem.validation.violations[0].code == "TYPE_MISMATCH_LITERAL"

    r_mal = gw.execute_query(
        ODataQueryParams(entity_set="A_PurchaseOrder", filter_expr="GrossAmount eq")
    )
    assert r_mal.validation.violations[0].code == "MALFORMED_FILTER_SYNTAX"

    r_unbal = gw.execute_query(
        ODataQueryParams(entity_set="A_PurchaseOrder", filter_expr="(GrossAmount gt 10")
    )
    assert r_unbal.validation.violations[0].code == "MALFORMED_FILTER_SYNTAX"

    # Non-numeric company code hashing + PII clearance True
    r_pii_ok = gw.execute_query(
        ODataQueryParams(
            entity_set="A_PurchaseOrder",
            expand=["to_PurchaseOrderItem"],
            principal=AgentPrincipal(
                allowed_company_codes=["1000", "DXB_ALPHA"], pii_clearance=True
            ),
        )
    )
    assert r_pii_ok.allowed is True
    assert r_pii_ok.redacted_fields == []
    assert r_pii_ok.rows[0]["VendorIBAN"].startswith("AE")

    # PO release missing PO & cross-company PO
    rel_missing = gw.simulate_po_release(
        PurchaseOrderReleaseRequest(
            purchase_order="9999999999", human_approval_token="APR-2026-OK1"
        )
    )
    assert rel_missing.allowed is False

    rel_cross = gw.simulate_po_release(
        PurchaseOrderReleaseRequest(
            purchase_order="4500010904",
            principal=AgentPrincipal(allowed_company_codes=["1000"]),
            human_approval_token="APR-2026-OK2",
        )
    )
    assert rel_cross.allowed is False
    assert any(v.code == "UNAUTHORIZED_COMPANY_CODE" for v in rel_cross.violations)

    # Verify audit chain intact, then simulate SHA-256 tamper
    assert gw.verify_audit_integrity()["valid"] is True
    gw._audit_log[0].sha256_chain_hex = "f" * 64
    tampered = gw.verify_audit_integrity()
    assert tampered["valid"] is False
    assert tampered["first_tampered_index"] == 0
