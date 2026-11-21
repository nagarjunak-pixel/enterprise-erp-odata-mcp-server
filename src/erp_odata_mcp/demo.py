"""Built-in enterprise SAP S/4HANA Clean-Core OData MCP guardrail audit scenarios."""

from __future__ import annotations

from typing import Any

from erp_odata_mcp.guardrails import ODataGuardrailGateway
from erp_odata_mcp.kernels import benchmark_kernels
from erp_odata_mcp.types import (
    AgentPrincipal,
    ODataQueryParams,
    PurchaseOrderReleaseRequest,
)


def run_demo_scenarios() -> dict[str, Any]:
    """Execute 6 enterprise ERP OData guardrail scenarios + C++20 kernel benchmark."""
    gw = ODataGuardrailGateway()
    dubai_agent = AgentPrincipal(
        agent_id="sap-procurement-copilot-dxb",
        allowed_company_codes=["1000"],
        pii_clearance=False,
    )

    # 1. Valid governed query: CompanyCode 1000 POs >= 25,000 AED (enforces BUKRS isolation + IBAN masking)
    s1_valid = gw.execute_query(
        ODataQueryParams(
            entity_set="A_PurchaseOrder",
            select=[
                "PurchaseOrder",
                "CompanyCode",
                "Supplier",
                "GrossAmount",
                "Currency",
                "VendorIBAN",
            ],
            filter_expr="GrossAmount ge 25000",
            orderby="GrossAmount desc",
            top=20,
            principal=dubai_agent,
        )
    )

    # 2. Hallucinated legacy SAP Z-field / raw BSEG column blocked by Clean-Core schema gate
    s2_hallucinated = gw.execute_query(
        ODataQueryParams(
            entity_set="A_PurchaseOrder",
            select=["PurchaseOrder", "ZZ_DIRTY_REBATE_CODE"],
            filter_expr="ZZ_DIRTY_REBATE_CODE eq 'X'",
            principal=dubai_agent,
        )
    )

    # 3. Prompt-injected OData $filter tautology (`or 1 eq 1`) blocked by C++20 scanner
    s3_injection = gw.execute_query(
        ODataQueryParams(
            entity_set="A_SalesOrder",
            filter_expr="CompanyCode eq '1000' or 1 eq 1",
            principal=dubai_agent,
        )
    )

    # 4. Unapproved PO release attempt blocked (missing human approval token)
    s4_unapproved = gw.simulate_po_release(
        PurchaseOrderReleaseRequest(
            purchase_order="4500010901",
            principal=dubai_agent,
            human_approval_token=None,
            reason="Autonomous agent attempting silent ERP write",
        )
    )

    # 5. Variance-blocked PO release rejected even WITH human token (3-way match failed!)
    s5_variance_blocked = gw.simulate_po_release(
        PurchaseOrderReleaseRequest(
            purchase_order="4500010902",
            principal=dubai_agent,
            human_approval_token="APR-2026-DXB-9941",
            reason="Attempt release on PO with GR/IR variance",
        )
    )

    # 6. Governed PO release succeeds (authorized BUKRS 1000 + human token + 3-way match MATCHED)
    s6_approved_release = gw.simulate_po_release(
        PurchaseOrderReleaseRequest(
            purchase_order="4500010901",
            principal=dubai_agent,
            human_approval_token="APR-2026-DXB-8820",
            reason="Controller verified 3-way match and approved release",
        )
    )

    audit_check = gw.verify_audit_integrity()
    bench = benchmark_kernels(num_rows=20000, audit_len=25000)

    return {
        "scenarios": [
            {
                "id": "1_governed_clean_query",
                "title": "Authorized Clean-Core Query + Cross-BUKRS Row Filter + IBAN Masking",
                "allowed": s1_valid.allowed,
                "returned_rows": s1_valid.count,
                "denied_cross_company_rows": s1_valid.denied_cross_company_rows,
                "redacted_fields": s1_valid.redacted_fields,
                "sample_row": s1_valid.rows[0] if s1_valid.rows else {},
            },
            {
                "id": "2_hallucinated_zfield_blocked",
                "title": "Hallucinated Legacy Z-Field (ZZ_DIRTY_REBATE_CODE) Blocked by Schema Gate",
                "allowed": s2_hallucinated.allowed,
                "violation_codes": [v.code for v in s2_hallucinated.validation.violations],
            },
            {
                "id": "3_odata_tautology_injection_blocked",
                "title": "Prompt-Injected OData Tautology ('or 1 eq 1') Blocked by C++20 Scanner",
                "allowed": s3_injection.allowed,
                "violation_codes": [v.code for v in s3_injection.validation.violations],
            },
            {
                "id": "4_silent_erp_mutation_blocked",
                "title": "Unapproved Autonomous PO Release Blocked (Missing Human Approval Token)",
                "allowed": s4_unapproved.allowed,
                "violation_codes": [v.code for v in s4_unapproved.violations],
            },
            {
                "id": "5_three_way_match_variance_blocked",
                "title": "3-Way-Match Variance Hold Enforced (Blocks PO 4500010902 Even With Token)",
                "allowed": s5_variance_blocked.allowed,
                "violation_codes": [v.code for v in s5_variance_blocked.violations],
            },
            {
                "id": "6_governed_po_release_succeeded",
                "title": "Human-Approved + 3-Way-Matched PO 4500010901 Released & Audited",
                "allowed": s6_approved_release.allowed,
                "new_status": s6_approved_release.new_status,
                "audit_seq": s6_approved_release.audit_seq,
            },
        ],
        "audit_integrity": audit_check,
        "kernel_benchmark": bench,
    }
