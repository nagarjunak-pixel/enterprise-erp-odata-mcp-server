# Security Policy

## Architectural Security Guarantees

1. **Clean-Core Metadata Whitelist:** Only explicitly released SAP S/4HANA OData v4 EntitySets (`A_PurchaseOrder`, `A_SalesOrder`, `A_JournalEntryItem`, `A_MaterialStock`) and typed EDM properties are addressable; raw legacy tables (`BSEG`, `EKKO`, `ZZ_*`) are deterministically rejected before network execution.
2. **Zero-`eval()` OData `$filter` Parser + C++20 Smuggling Scanner:** `csrc/odata_guard_kernels.cpp` scans `$filter` strings in `O(N)` for SQL/ABAP comments, semicolons, `$batch` boundary smuggling, unclosed quotes, and `1 eq 1` tautologies before the recursive-descent EDM type-checker runs.
3. **Out-of-Prompt `BUKRS` Isolation, PII Redaction & Human Approval Gate:** CompanyCode (`BUKRS`) row filtering, IBAN/Tax-ID masking, and mutating action approval tokens (`APR-...` + 3-way match verification) execute outside the LLM prompt and log to a SHA-256 + SplitMix64 hash chain.

## Reporting a Vulnerability

Report security issues privately to `writetonagarjuna@gmail.com`.
