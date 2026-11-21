"""Governed SAP S/4HANA OData v4 query engine, PII redactor, PO release gate & audit ledger."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from erp_odata_mcp.guardrails.filter_ast import (
    FilterNode,
    FilterParseError,
    FilterTypeMismatchError,
    UnfilterableFieldError,
    UnknownFilterFieldError,
    evaluate_filter_ast,
    parse_odata_filter,
)
from erp_odata_mcp.kernels import (
    GENESIS_SEED,
    backend_name,
    filter_company_rows,
    scan_filter_security,
    step_audit_hash,
    verify_audit_chain,
)
from erp_odata_mcp.schema import ENTITY_SCHEMAS, create_sandbox_rows, get_entity_schema
from erp_odata_mcp.types import (
    AuditEntry,
    EntitySetSchema,
    GuardrailViolation,
    ODataQueryParams,
    ODataQueryResponse,
    PurchaseOrderReleaseRequest,
    PurchaseOrderReleaseResponse,
    QueryValidationReport,
)


def _bukrs_to_int(code: str) -> int:
    if code.isdigit():
        return int(code)
    digest = hashlib.sha256(code.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


def _mask_pii_value(raw: Any) -> str:
    s = str(raw)
    if len(s) <= 6:
        return "***REDACTED***"
    return f"{s[:4]}***REDACTED***{s[-3:]}"


class ODataGuardrailGateway:
    """Clean-Core SAP S/4HANA OData v4 execution gateway with C++20 security & RBAC kernels."""

    def __init__(self) -> None:
        self._store: dict[str, list[dict[str, Any]]] = create_sandbox_rows()
        self._audit_log: list[AuditEntry] = []
        self._prev_u64: int = GENESIS_SEED
        self._prev_sha256: str = "0" * 64

    def list_schemas(self) -> list[EntitySetSchema]:
        return list(ENTITY_SCHEMAS.values())

    def get_audit_log(self) -> list[AuditEntry]:
        return list(self._audit_log)

    def verify_audit_integrity(self, *, use_native: bool = True) -> dict[str, Any]:
        payloads = [e.payload_hash_u64 for e in self._audit_log]
        recorded = [e.chain_hash_u64 for e in self._audit_log]
        ok_u64, bad_idx = verify_audit_chain(payloads, recorded, use_native=use_native)

        prev_hex = "0" * 64
        sha_ok = True
        for idx, entry in enumerate(self._audit_log):
            expected_sha = hashlib.sha256(
                f"{prev_hex}:{entry.seq}:{entry.payload_hash_u64}".encode()
            ).hexdigest()
            if entry.sha256_chain_hex != expected_sha:
                sha_ok = False
                if bad_idx == -1:
                    bad_idx = idx
                break
            prev_hex = expected_sha

        return {
            "valid": ok_u64 and sha_ok,
            "records_checked": len(self._audit_log),
            "first_tampered_index": bad_idx,
            "backend": backend_name(),
        }

    def _record_audit(
        self,
        agent_id: str,
        tool_name: str,
        entity_set: str,
        allowed: bool,
        violation_codes: list[str],
        detail: dict[str, Any],
    ) -> AuditEntry:
        seq = len(self._audit_log) + 1
        canonical = json.dumps(
            {
                "seq": seq,
                "agent_id": agent_id,
                "tool": tool_name,
                "entity": entity_set,
                "allowed": allowed,
                "violations": violation_codes,
                "detail": detail,
            },
            sort_keys=True,
        ).encode("utf-8")
        payload_u64 = int.from_bytes(hashlib.sha256(canonical).digest()[:8], "big")
        next_u64 = step_audit_hash(self._prev_u64, payload_u64)
        next_sha = hashlib.sha256(f"{self._prev_sha256}:{seq}:{payload_u64}".encode()).hexdigest()

        entry = AuditEntry(
            seq=seq,
            timestamp_utc=datetime.now(UTC).isoformat(),
            agent_id=agent_id,
            tool_name=tool_name,
            entity_set=entity_set,
            allowed=allowed,
            violation_codes=violation_codes,
            payload_hash_u64=payload_u64,
            chain_hash_u64=next_u64,
            sha256_chain_hex=next_sha,
        )
        self._prev_u64 = next_u64
        self._prev_sha256 = next_sha
        self._audit_log.append(entry)
        return entry

    def validate_query(
        self, params: ODataQueryParams, *, use_native: bool = True
    ) -> tuple[QueryValidationReport, FilterNode | None]:
        scan = scan_filter_security(params.filter_expr, use_native=use_native)
        violations: list[GuardrailViolation] = []
        parsed_ast: FilterNode | None = None

        schema = get_entity_schema(params.entity_set)
        if schema is None:
            valid_names = ", ".join(sorted(ENTITY_SCHEMAS.keys()))
            violations.append(
                GuardrailViolation(
                    code="UNKNOWN_ENTITY_SET",
                    field=params.entity_set,
                    message=f"EntitySet {params.entity_set!r} is not a released SAP S/4HANA Clean-Core OData v4 service.",
                    remediation=f"Use a released Clean-Core API EntitySet: {valid_names}. Never query raw SAP tables (BSEG/EKKO/VBAK).",
                )
            )
            return (
                QueryValidationReport(
                    allowed=False,
                    entity_set=params.entity_set,
                    filter_scan=scan,
                    violations=violations,
                    normalized_odata_url=f"/sap/opu/odata4/sap/clean_core/srvd_a2x/{params.entity_set}",
                ),
                None,
            )

        prop_map = {p.name: p for p in schema.properties}
        valid_fields_str = ", ".join(prop_map.keys())

        if params.top < 0 or params.skip < 0:
            violations.append(
                GuardrailViolation(
                    code="NEGATIVE_PAGINATION",
                    message=f"$top ({params.top}) and $skip ({params.skip}) must be >= 0.",
                    remediation="Pass positive bounded $top and non-negative $skip.",
                )
            )
        elif params.top > schema.max_top:
            violations.append(
                GuardrailViolation(
                    code="TOP_LIMIT_EXCEEDED",
                    field="$top",
                    message=f"$top={params.top} exceeds Clean-Core entity cap max_top={schema.max_top} for {schema.name}.",
                    remediation=f"Reduce $top to <= {schema.max_top} and page with $skip.",
                )
            )

        for sel_field in params.select:
            if sel_field not in prop_map:
                violations.append(
                    GuardrailViolation(
                        code="UNKNOWN_SELECT_FIELD",
                        field=sel_field,
                        message=f"Hallucinated or unexposed field {sel_field!r} in $select on {schema.name}.",
                        remediation=f"Select only released {schema.clean_core_cds} fields: {valid_fields_str}.",
                    )
                )

        for exp in params.expand:
            if exp not in schema.allowed_expands:
                violations.append(
                    GuardrailViolation(
                        code="DISALLOWED_EXPAND",
                        field=exp,
                        message=f"Navigation $expand={exp!r} is not permitted on {schema.name}.",
                        remediation=f"Allowed $expand navigations: {schema.allowed_expands or 'none'}.",
                    )
                )

        if params.orderby:
            parts = params.orderby.strip().split()
            ob_field = parts[0]
            ob_dir = parts[1].lower() if len(parts) > 1 else "asc"
            if len(parts) > 2 or ob_dir not in {"asc", "desc"} or ob_field not in prop_map:
                violations.append(
                    GuardrailViolation(
                        code="UNKNOWN_ORDERBY_FIELD",
                        field=params.orderby,
                        message=f"Invalid $orderby clause {params.orderby!r} on {schema.name}.",
                        remediation=f"Use '<Field> asc|desc' with a sortable field from: {valid_fields_str}.",
                    )
                )
            elif not prop_map[ob_field].sortable:
                violations.append(
                    GuardrailViolation(
                        code="UNKNOWN_ORDERBY_FIELD",
                        field=ob_field,
                        message=f"Field {ob_field!r} is restricted/PII and cannot be used in $orderby.",
                        remediation="Sort on a non-PII business key or amount field.",
                    )
                )

        if not params.principal.allowed_company_codes:
            violations.append(
                GuardrailViolation(
                    code="UNAUTHORIZED_COMPANY_CODE",
                    field="CompanyCode",
                    message="Caller principal has zero authorized SAP CompanyCodes (BUKRS).",
                    remediation="Provide at least one authorized BUKRS in principal.allowed_company_codes.",
                )
            )

        if params.filter_expr:
            if scan.has_injection_pattern:
                violations.append(
                    GuardrailViolation(
                        code="FILTER_INJECTION_BLOCKED",
                        field="$filter",
                        message="C++20 security scanner blocked tautology, comment, or $batch smuggling pattern in $filter.",
                        remediation="Remove tautologies (1 eq 1), SQL/ABAP comments (--, /*), semicolons, and $batch directives.",
                    )
                )
            if not scan.paren_balanced or scan.unclosed_quote:
                violations.append(
                    GuardrailViolation(
                        code="MALFORMED_FILTER_SYNTAX",
                        field="$filter",
                        message="Unbalanced parentheses or unclosed string literal in $filter.",
                        remediation="Balance all parentheses and single-quoted OData string literals.",
                    )
                )
            if scan.cost_score > params.principal.max_cost_budget or scan.boolean_clause_count > 12:
                violations.append(
                    GuardrailViolation(
                        code="QUERY_COST_EXCEEDED",
                        field="$filter",
                        message=f"$filter complexity score {scan.cost_score} ({scan.boolean_clause_count} clauses) exceeds budget {params.principal.max_cost_budget}.",
                        remediation="Simplify boolean fan-out and nesting depth in $filter.",
                    )
                )

            if not any(
                v.code in {"MALFORMED_FILTER_SYNTAX", "FILTER_INJECTION_BLOCKED"}
                for v in violations
            ):
                try:
                    parsed_ast = parse_odata_filter(params.filter_expr, schema)
                except UnknownFilterFieldError as exc:
                    violations.append(
                        GuardrailViolation(
                            code="UNKNOWN_FILTER_FIELD",
                            field=exc.field,
                            message=f"Unknown or non-Clean-Core field {exc.field!r} in $filter.",
                            remediation=f"Filter only on released {schema.clean_core_cds} fields: {valid_fields_str}.",
                        )
                    )
                except UnfilterableFieldError as exc:
                    violations.append(
                        GuardrailViolation(
                            code="UNFILTERABLE_FIELD",
                            field=exc.field,
                            message=f"Sensitive/PII field {exc.field!r} cannot be probed via $filter predicates.",
                            remediation="Filter on non-PII business keys instead.",
                        )
                    )
                except FilterTypeMismatchError as exc:
                    violations.append(
                        GuardrailViolation(
                            code="TYPE_MISMATCH_LITERAL",
                            field=exc.field,
                            message=str(exc),
                            remediation="Match OData literal syntax to EDM type (quoted strings for Edm.String/Edm.Date, bare numbers for Edm.Decimal/Edm.Int32, true/false for Edm.Boolean).",
                        )
                    )
                except FilterParseError as exc:
                    violations.append(
                        GuardrailViolation(
                            code="MALFORMED_FILTER_SYNTAX",
                            field="$filter",
                            message=str(exc),
                            remediation="Use valid OData v4 syntax, e.g. CompanyCode eq '1000' and GrossAmount ge 10000.",
                        )
                    )

        q_dict: dict[str, str] = {"$top": str(params.top), "$skip": str(params.skip)}
        if params.select:
            q_dict["$select"] = ",".join(params.select)
        if params.filter_expr:
            q_dict["$filter"] = params.filter_expr
        if params.orderby:
            q_dict["$orderby"] = params.orderby
        if params.expand:
            q_dict["$expand"] = ",".join(params.expand)

        norm_url = (
            f"/sap/opu/odata4/sap/clean_core/srvd_a2x/{params.entity_set}?{urlencode(q_dict)}"
        )
        return (
            QueryValidationReport(
                allowed=len(violations) == 0,
                entity_set=params.entity_set,
                filter_scan=scan,
                violations=violations,
                normalized_odata_url=norm_url,
            ),
            parsed_ast,
        )

    def execute_query(
        self, params: ODataQueryParams, *, use_native: bool = True
    ) -> ODataQueryResponse:
        validation, parsed_ast = self.validate_query(params, use_native=use_native)
        if not validation.allowed:
            entry = self._record_audit(
                params.principal.agent_id,
                "odata_query_entities",
                params.entity_set,
                False,
                [v.code for v in validation.violations],
                {"url": validation.normalized_odata_url},
            )
            return ODataQueryResponse(
                allowed=False,
                entity_set=params.entity_set,
                backend=backend_name(),
                odata_context=f"$metadata#{params.entity_set}",
                count=0,
                denied_cross_company_rows=0,
                redacted_fields=[],
                rows=[],
                validation=validation,
                audit_seq=entry.seq,
                audit_chain_hex=entry.sha256_chain_hex,
            )

        schema = ENTITY_SCHEMAS[params.entity_set]
        all_rows = self._store[params.entity_set]

        # Step 1: Evaluate validated OData $filter AST first across candidate rows
        predicate_matched = (
            [r for r in all_rows if evaluate_filter_ast(parsed_ast, r)]
            if parsed_ast is not None
            else list(all_rows)
        )

        # Optional deterministic $orderby before $skip/$top pagination
        if params.orderby:
            parts = params.orderby.strip().split()
            ob_field = parts[0]
            reverse = len(parts) > 1 and parts[1].lower() == "desc"
            predicate_matched.sort(key=lambda r: r[ob_field], reverse=reverse)

        # Step 2: Enforce C++20 vectorized CompanyCode (BUKRS) row-level RBAC + $skip/$top
        row_codes = [_bukrs_to_int(str(r[schema.company_code_field])) for r in predicate_matched]
        allowed_codes = [_bukrs_to_int(c) for c in params.principal.allowed_company_codes]
        selected_idx, denied_cnt = filter_company_rows(
            row_codes,
            allowed_codes,
            top_limit=params.top,
            skip_offset=params.skip,
            use_native=use_native,
        )

        pii_fields = {p.name for p in schema.properties if p.is_pii}
        redacted_names: set[str] = set()
        projected_rows: list[dict[str, Any]] = []
        keep_fields = set(params.select) if params.select else {p.name for p in schema.properties}

        for i in selected_idx:
            src = predicate_matched[i]
            out_row: dict[str, Any] = {}
            for k in [p.name for p in schema.properties if p.name in keep_fields]:
                val = src[k]
                if k in pii_fields and not params.principal.pii_clearance:
                    out_row[k] = _mask_pii_value(val)
                    redacted_names.add(k)
                else:
                    out_row[k] = val
            projected_rows.append(out_row)

        entry = self._record_audit(
            params.principal.agent_id,
            "odata_query_entities",
            params.entity_set,
            True,
            [],
            {
                "url": validation.normalized_odata_url,
                "returned": len(projected_rows),
                "denied_cross_company_rows": denied_cnt,
            },
        )
        return ODataQueryResponse(
            allowed=True,
            entity_set=params.entity_set,
            backend=backend_name(),
            odata_context=f"$metadata#{params.entity_set}",
            count=len(projected_rows),
            denied_cross_company_rows=denied_cnt,
            redacted_fields=sorted(redacted_names),
            rows=projected_rows,
            validation=validation,
            audit_seq=entry.seq,
            audit_chain_hex=entry.sha256_chain_hex,
        )

    def simulate_po_release(self, req: PurchaseOrderReleaseRequest) -> PurchaseOrderReleaseResponse:
        """Execute a governed SAP MM Purchase Order release gated by human approval & 3-way match."""
        violations: list[GuardrailViolation] = []
        po_rows = self._store["A_PurchaseOrder"]
        target: dict[str, Any] | None = next(
            (r for r in po_rows if r["PurchaseOrder"] == req.purchase_order), None
        )

        if target is None:
            violations.append(
                GuardrailViolation(
                    code="UNKNOWN_FILTER_FIELD",
                    field="PurchaseOrder",
                    message=f"PurchaseOrder {req.purchase_order!r} does not exist in A_PurchaseOrder.",
                    remediation="Query A_PurchaseOrder first to verify the PurchaseOrder key.",
                )
            )
        else:
            if target["CompanyCode"] not in req.principal.allowed_company_codes:
                violations.append(
                    GuardrailViolation(
                        code="UNAUTHORIZED_COMPANY_CODE",
                        field="CompanyCode",
                        message=f"Principal {req.principal.agent_id!r} is not authorized for CompanyCode {target['CompanyCode']!r}.",
                        remediation="Request CompanyCode delegation before releasing cross-entity POs.",
                    )
                )
            token = (req.human_approval_token or "").strip()
            if not token.startswith("APR-") or len(token) < 10:
                violations.append(
                    GuardrailViolation(
                        code="MISSING_HUMAN_APPROVAL",
                        field="human_approval_token",
                        message="Mutating ERP OData action blocked: valid fresh human approval token (APR-...) is mandatory.",
                        remediation="Obtain human supervisor sign-off token before invoking PurchaseOrder release.",
                    )
                )
            if target["ThreeWayMatchStatus"] != "MATCHED" or bool(target["IsBlocked"]):
                violations.append(
                    GuardrailViolation(
                        code="THREE_WAY_MATCH_FAILED",
                        field="ThreeWayMatchStatus",
                        message=(
                            f"PO {req.purchase_order} has ThreeWayMatchStatus={target['ThreeWayMatchStatus']!r} "
                            f"(IsBlocked={target['IsBlocked']}) — release forbidden."
                        ),
                        remediation="Resolve Goods Receipt / Invoice Receipt variance in SAP MM before releasing.",
                    )
                )

        if violations or target is None:
            entry = self._record_audit(
                req.principal.agent_id,
                "odata_simulate_po_release",
                "A_PurchaseOrder",
                False,
                [v.code for v in violations],
                {"purchase_order": req.purchase_order},
            )
            return PurchaseOrderReleaseResponse(
                allowed=False,
                purchase_order=req.purchase_order,
                previous_status=target["ReleaseStatus"] if target else None,
                new_status=target["ReleaseStatus"] if target else None,
                violations=violations,
                audit_seq=entry.seq,
                audit_chain_hex=entry.sha256_chain_hex,
            )

        prev_status = str(target["ReleaseStatus"])
        target["ReleaseStatus"] = "RELEASED"
        entry = self._record_audit(
            req.principal.agent_id,
            "odata_simulate_po_release",
            "A_PurchaseOrder",
            True,
            [],
            {"purchase_order": req.purchase_order, "approval_token": req.human_approval_token},
        )
        return PurchaseOrderReleaseResponse(
            allowed=True,
            purchase_order=req.purchase_order,
            previous_status=prev_status,
            new_status="RELEASED",
            violations=[],
            audit_seq=entry.seq,
            audit_chain_hex=entry.sha256_chain_hex,
        )
