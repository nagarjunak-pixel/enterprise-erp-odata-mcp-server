import React, { useEffect, useState } from "react";

interface Violation {
  code: string;
  field: string | null;
  message: string;
  remediation: string;
}

interface QueryResponse {
  allowed: boolean;
  entity_set: string;
  backend: string;
  count: number;
  denied_cross_company_rows: number;
  redacted_fields: string[];
  rows: Record<string, unknown>[];
  audit_seq: number;
  audit_chain_hex: string;
  validation: {
    normalized_odata_url: string;
    violations: Violation[];
    filter_scan: {
      boolean_clause_count: number;
      max_paren_depth: number;
      cost_score: number;
      has_injection_pattern: boolean;
    };
  };
}

export function App(): React.JSX.Element {
  const [entitySet, setEntitySet] = useState<string>("A_PurchaseOrder");
  const [filterExpr, setFilterExpr] = useState<string>("GrossAmount ge 25000");
  const [selectFields, setSelectFields] = useState<string>(
    "PurchaseOrder,CompanyCode,Supplier,GrossAmount,Currency,VendorIBAN"
  );
  const [companyCodes, setCompanyCodes] = useState<string>("1000");
  const [result, setResult] = useState<QueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function executeQuery(
    ent: string,
    filt: string,
    sel: string,
    bukrs: string
  ): Promise<void> {
    setError(null);
    try {
      const resp = await fetch("/api/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entity_set: ent,
          filter_expr: filt.trim() || null,
          select: sel
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          top: 50,
          principal: {
            agent_id: "workbench-sap-copilot",
            allowed_company_codes: bukrs
              .split(",")
              .map((c) => c.trim())
              .filter(Boolean),
            pii_clearance: false
          }
        })
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      setResult((await resp.json()) as QueryResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "API unreachable (:8270)");
    }
  }

  useEffect(() => {
    void executeQuery(entitySet, filterExpr, selectFields, companyCodes);
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <span className="eyebrow">
            Enterprise ERP OData MCP Server v1.0.0 · Port 8270 · SAP S/4HANA Clean-Core + C++20 Guardrails
          </span>
          <h1>OData v4 Schema Validator, BUKRS Row RBAC &amp; Tool-Calling Guardrails</h1>
        </div>
        <div className="presets">
          <button
            type="button"
            onClick={() => {
              setEntitySet("A_PurchaseOrder");
              setFilterExpr("GrossAmount ge 25000");
              setSelectFields("PurchaseOrder,CompanyCode,Supplier,GrossAmount,Currency,VendorIBAN");
              void executeQuery(
                "A_PurchaseOrder",
                "GrossAmount ge 25000",
                "PurchaseOrder,CompanyCode,Supplier,GrossAmount,Currency,VendorIBAN",
                companyCodes
              );
            }}
          >
            Clean-Core PO Query
          </button>
          <button
            type="button"
            onClick={() => {
              setEntitySet("A_PurchaseOrder");
              setFilterExpr("ZZ_DIRTY_REBATE eq 'X'");
              void executeQuery(
                "A_PurchaseOrder",
                "ZZ_DIRTY_REBATE eq 'X'",
                selectFields,
                companyCodes
              );
            }}
          >
            Test Dirty Z-Field Block
          </button>
          <button
            type="button"
            onClick={() => {
              setEntitySet("A_SalesOrder");
              setFilterExpr("CompanyCode eq '1000' or 1 eq 1");
              setSelectFields("SalesOrder,CompanyCode,NetAmount,Currency");
              void executeQuery(
                "A_SalesOrder",
                "CompanyCode eq '1000' or 1 eq 1",
                "SalesOrder,CompanyCode,NetAmount,Currency",
                companyCodes
              );
            }}
          >
            Test $filter Tautology Attack
          </button>
        </div>
      </header>

      {error && <div className="alert-err">{error}</div>}

      <main className="grid">
        <section className="panel">
          <h2>OData v4 MCP Tool Request</h2>
          <label>
            EntitySet (Clean-Core Released Service)
            <select value={entitySet} onChange={(e) => setEntitySet(e.target.value)}>
              <option value="A_PurchaseOrder">A_PurchaseOrder (SAP MM)</option>
              <option value="A_SalesOrder">A_SalesOrder (SAP SD)</option>
              <option value="A_JournalEntryItem">A_JournalEntryItem (SAP FI ACDOCA)</option>
              <option value="A_MaterialStock">A_MaterialStock (SAP MM-IM)</option>
              <option value="BSEG_RAW_TABLE">BSEG_RAW_TABLE (Forbidden Raw Table)</option>
            </select>
          </label>
          <label>
            $filter Expression
            <input value={filterExpr} onChange={(e) => setFilterExpr(e.target.value)} />
          </label>
          <label>
            $select Properties (comma-separated)
            <input value={selectFields} onChange={(e) => setSelectFields(e.target.value)} />
          </label>
          <label>
            Authorized CompanyCodes (BUKRS)
            <input value={companyCodes} onChange={(e) => setCompanyCodes(e.target.value)} />
          </label>
          <button
            type="button"
            className="btn-primary"
            onClick={() => void executeQuery(entitySet, filterExpr, selectFields, companyCodes)}
          >
            Validate &amp; Execute Governed OData Query
          </button>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Guardrail Verdict &amp; Audited Payload</h2>
            {result && (
              <span className={result.allowed ? "badge pass" : "badge fail"}>
                {result.allowed ? "ALLOWED & MASKED" : "BLOCKED BY GUARDRAIL"}
              </span>
            )}
          </div>
          {result && (
            <>
              <div className="kpis">
                <div className="kpi">
                  <span>Rows Returned</span>
                  <strong>{result.count}</strong>
                </div>
                <div className="kpi">
                  <span>Cross-BUKRS Filtered</span>
                  <strong>{result.denied_cross_company_rows}</strong>
                </div>
                <div className="kpi">
                  <span>PII Redacted</span>
                  <strong>{result.redacted_fields.join(", ") || "None"}</strong>
                </div>
                <div className="kpi">
                  <span>Audit Seq</span>
                  <strong>#{result.audit_seq}</strong>
                </div>
              </div>
              <p className="url-line">
                <code>{result.validation.normalized_odata_url}</code>
              </p>
              {result.validation.violations.map((v, idx) => (
                <div key={idx} className="violation">
                  <strong>[{v.code}]</strong> {v.message}
                  <div className="rem">Remediation: {v.remediation}</div>
                </div>
              ))}
              <pre className="json-box">{JSON.stringify(result.rows, null, 2)}</pre>
            </>
          )}
        </section>
      </main>
    </div>
  );
}
