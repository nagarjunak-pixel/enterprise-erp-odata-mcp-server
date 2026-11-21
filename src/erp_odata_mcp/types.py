"""Strict Pydantic v2 schemas for OData v4 metadata, query AST, guardrails, and audit records."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EdmType = Literal["Edm.String", "Edm.Decimal", "Edm.Int32", "Edm.Boolean", "Edm.Date"]


class EdmPropertySpec(BaseModel):
    """Typed OData v4 Entity Data Model (CSDL) property definition."""

    name: str
    edm_type: EdmType
    is_key: bool = False
    filterable: bool = True
    sortable: bool = True
    is_pii: bool = False
    description: str = ""


class EntitySetSchema(BaseModel):
    """SAP S/4HANA Clean-Core OData v4 EntitySet contract."""

    name: str
    sap_module: Literal["MM", "SD", "FI", "MM-IM"]
    clean_core_cds: str
    description: str
    company_code_field: str = "CompanyCode"
    max_top: int = 200
    allowed_expands: list[str] = Field(default_factory=list)
    properties: list[EdmPropertySpec]


class AgentPrincipal(BaseModel):
    """Caller authorization context enforced outside the LLM prompt."""

    agent_id: str = "claude-erp-copilot"
    allowed_company_codes: list[str] = Field(default_factory=lambda: ["1000"])
    pii_clearance: bool = False
    max_cost_budget: int = 120


class ODataQueryParams(BaseModel):
    """Structured OData v4 query request parameters."""

    entity_set: str
    select: list[str] = Field(default_factory=list)
    filter_expr: str | None = None
    orderby: str | None = None
    expand: list[str] = Field(default_factory=list)
    top: int = 50
    skip: int = 0
    principal: AgentPrincipal = Field(default_factory=AgentPrincipal)


class FilterSecurityScan(BaseModel):
    """C++20 / Python lexical & structural scan metrics for an OData `$filter` string."""

    paren_balanced: bool
    max_paren_depth: int
    boolean_clause_count: int
    has_injection_pattern: bool
    unclosed_quote: bool
    cost_score: int
    backend: str


GuardrailViolationCode = Literal[
    "UNKNOWN_ENTITY_SET",
    "UNKNOWN_SELECT_FIELD",
    "UNKNOWN_FILTER_FIELD",
    "UNFILTERABLE_FIELD",
    "UNKNOWN_ORDERBY_FIELD",
    "DISALLOWED_EXPAND",
    "TOP_LIMIT_EXCEEDED",
    "NEGATIVE_PAGINATION",
    "MALFORMED_FILTER_SYNTAX",
    "FILTER_INJECTION_BLOCKED",
    "QUERY_COST_EXCEEDED",
    "TYPE_MISMATCH_LITERAL",
    "UNAUTHORIZED_COMPANY_CODE",
    "MISSING_HUMAN_APPROVAL",
    "THREE_WAY_MATCH_FAILED",
]


class GuardrailViolation(BaseModel):
    """Single deterministic schema or tool-calling guardrail rejection."""

    code: GuardrailViolationCode
    field: str | None = None
    message: str
    remediation: str


class QueryValidationReport(BaseModel):
    """Pre-execution validation verdict before any ERP OData request executes."""

    allowed: bool
    entity_set: str
    filter_scan: FilterSecurityScan
    violations: list[GuardrailViolation] = Field(default_factory=list)
    normalized_odata_url: str


class ODataQueryResponse(BaseModel):
    """Governed OData v4 query execution response with redaction & audit metadata."""

    allowed: bool
    entity_set: str
    backend: str
    odata_context: str
    count: int
    denied_cross_company_rows: int
    redacted_fields: list[str]
    rows: list[dict[str, Any]]
    validation: QueryValidationReport
    audit_seq: int
    audit_chain_hex: str


class PurchaseOrderReleaseRequest(BaseModel):
    """Controlled write/action-import simulation gated by human approval & 3-way match."""

    purchase_order: str
    principal: AgentPrincipal = Field(default_factory=AgentPrincipal)
    human_approval_token: str | None = None
    reason: str = ""


class PurchaseOrderReleaseResponse(BaseModel):
    """Result of governed Purchase Order release action import."""

    allowed: bool
    purchase_order: str
    previous_status: str | None = None
    new_status: str | None = None
    violations: list[GuardrailViolation] = Field(default_factory=list)
    audit_seq: int
    audit_chain_hex: str


class AuditEntry(BaseModel):
    """Tamper-evident ERP MCP tool-call audit log record."""

    seq: int
    timestamp_utc: str
    agent_id: str
    tool_name: str
    entity_set: str
    allowed: bool
    violation_codes: list[str]
    payload_hash_u64: int
    chain_hash_u64: int
    sha256_chain_hex: str
