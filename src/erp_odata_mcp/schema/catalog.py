"""Clean-Core SAP S/4HANA OData v4 metadata catalog (`MM`, `SD`, `FI`, `MM-IM`) and seed data."""

from __future__ import annotations

import copy
from typing import Any

from erp_odata_mcp.types import EdmPropertySpec, EntitySetSchema

ENTITY_SCHEMAS: dict[str, EntitySetSchema] = {
    "A_PurchaseOrder": EntitySetSchema(
        name="A_PurchaseOrder",
        sap_module="MM",
        clean_core_cds="I_PurchaseOrderAPI01",
        description="SAP S/4HANA Procure-to-Pay Purchase Orders (Clean-Core released OData v4 API).",
        max_top=100,
        allowed_expands=["to_PurchaseOrderItem"],
        properties=[
            EdmPropertySpec(name="PurchaseOrder", edm_type="Edm.String", is_key=True),
            EdmPropertySpec(name="CompanyCode", edm_type="Edm.String"),
            EdmPropertySpec(name="PurchasingOrg", edm_type="Edm.String"),
            EdmPropertySpec(name="Supplier", edm_type="Edm.String"),
            EdmPropertySpec(name="GrossAmount", edm_type="Edm.Decimal"),
            EdmPropertySpec(name="Currency", edm_type="Edm.String"),
            EdmPropertySpec(name="ReleaseStatus", edm_type="Edm.String"),
            EdmPropertySpec(name="ThreeWayMatchStatus", edm_type="Edm.String"),
            EdmPropertySpec(name="IsBlocked", edm_type="Edm.Boolean"),
            EdmPropertySpec(name="CreationDate", edm_type="Edm.Date"),
            EdmPropertySpec(
                name="VendorIBAN",
                edm_type="Edm.String",
                filterable=False,
                sortable=False,
                is_pii=True,
                description="Sensitive supplier bank IBAN — masked unless pii_clearance=True",
            ),
        ],
    ),
    "A_SalesOrder": EntitySetSchema(
        name="A_SalesOrder",
        sap_module="SD",
        clean_core_cds="I_SalesOrderAPI01",
        description="SAP S/4HANA Order-to-Cash Sales Orders with credit-exposure status.",
        max_top=100,
        allowed_expands=["to_Item", "to_Partner"],
        properties=[
            EdmPropertySpec(name="SalesOrder", edm_type="Edm.String", is_key=True),
            EdmPropertySpec(name="CompanyCode", edm_type="Edm.String"),
            EdmPropertySpec(name="SalesOrg", edm_type="Edm.String"),
            EdmPropertySpec(name="SoldToParty", edm_type="Edm.String"),
            EdmPropertySpec(name="NetAmount", edm_type="Edm.Decimal"),
            EdmPropertySpec(name="Currency", edm_type="Edm.String"),
            EdmPropertySpec(name="CreditBlockStatus", edm_type="Edm.String"),
            EdmPropertySpec(name="DeliveryStatus", edm_type="Edm.String"),
            EdmPropertySpec(
                name="CustomerTaxId",
                edm_type="Edm.String",
                filterable=False,
                sortable=False,
                is_pii=True,
            ),
        ],
    ),
    "A_JournalEntryItem": EntitySetSchema(
        name="A_JournalEntryItem",
        sap_module="FI",
        clean_core_cds="I_JournalEntryItemCube",
        description="SAP S/4HANA Universal Journal (ACDOCA Clean-Core analytical projection).",
        max_top=200,
        allowed_expands=[],
        properties=[
            EdmPropertySpec(name="AccountingDocument", edm_type="Edm.String", is_key=True),
            EdmPropertySpec(name="CompanyCode", edm_type="Edm.String"),
            EdmPropertySpec(name="FiscalYear", edm_type="Edm.Int32"),
            EdmPropertySpec(name="GLAccount", edm_type="Edm.String"),
            EdmPropertySpec(name="CostCenter", edm_type="Edm.String"),
            EdmPropertySpec(name="DebitCreditCode", edm_type="Edm.String"),
            EdmPropertySpec(name="AmountInCompanyCodeCurrency", edm_type="Edm.Decimal"),
            EdmPropertySpec(name="PostingDate", edm_type="Edm.Date"),
        ],
    ),
    "A_MaterialStock": EntitySetSchema(
        name="A_MaterialStock",
        sap_module="MM-IM",
        clean_core_cds="I_MaterialStock_2",
        description="SAP S/4HANA Plant & Storage Location Inventory Stock.",
        max_top=200,
        allowed_expands=[],
        properties=[
            EdmPropertySpec(name="Material", edm_type="Edm.String", is_key=True),
            EdmPropertySpec(name="CompanyCode", edm_type="Edm.String"),
            EdmPropertySpec(name="Plant", edm_type="Edm.String"),
            EdmPropertySpec(name="StorageLocation", edm_type="Edm.String"),
            EdmPropertySpec(name="UnrestrictedStockQty", edm_type="Edm.Int32"),
            EdmPropertySpec(name="SafetyStockQty", edm_type="Edm.Int32"),
            EdmPropertySpec(name="BaseUnit", edm_type="Edm.String"),
        ],
    ),
}


def get_entity_schema(entity_set: str) -> EntitySetSchema | None:
    """Lookup released Clean-Core OData v4 EntitySet metadata."""
    return ENTITY_SCHEMAS.get(entity_set)


def create_sandbox_rows() -> dict[str, list[dict[str, Any]]]:
    """Return fresh deterministic multi-company SAP S/4HANA OData v4 records."""
    return copy.deepcopy(
        {
            "A_PurchaseOrder": [
                {
                    "PurchaseOrder": "4500010901",
                    "CompanyCode": "1000",
                    "PurchasingOrg": "DXB1",
                    "Supplier": "VEND-ALFUTTAIM-01",
                    "GrossAmount": 148500.00,
                    "Currency": "AED",
                    "ReleaseStatus": "PENDING_APPROVAL",
                    "ThreeWayMatchStatus": "MATCHED",
                    "IsBlocked": False,
                    "CreationDate": "2026-11-18",
                    "VendorIBAN": "AE070331234567890123456",
                },
                {
                    "PurchaseOrder": "4500010902",
                    "CompanyCode": "1000",
                    "PurchasingOrg": "DXB1",
                    "Supplier": "VEND-GULFCLOUD-09",
                    "GrossAmount": 32400.00,
                    "Currency": "AED",
                    "ReleaseStatus": "PENDING_APPROVAL",
                    "ThreeWayMatchStatus": "VARIANCE_HOLD",
                    "IsBlocked": True,
                    "CreationDate": "2026-11-19",
                    "VendorIBAN": "AE420269876543210987654",
                },
                {
                    "PurchaseOrder": "4500010903",
                    "CompanyCode": "2000",
                    "PurchasingOrg": "RUH1",
                    "Supplier": "VEND-RIYADHTECH-04",
                    "GrossAmount": 295000.00,
                    "Currency": "SAR",
                    "ReleaseStatus": "RELEASED",
                    "ThreeWayMatchStatus": "MATCHED",
                    "IsBlocked": False,
                    "CreationDate": "2026-11-20",
                    "VendorIBAN": "SA0380000000608010167519",
                },
                {
                    "PurchaseOrder": "4500010904",
                    "CompanyCode": "3000",
                    "PurchasingOrg": "LON1",
                    "Supplier": "VEND-THAMESBIO-02",
                    "GrossAmount": 84000.00,
                    "Currency": "GBP",
                    "ReleaseStatus": "RELEASED",
                    "ThreeWayMatchStatus": "MATCHED",
                    "IsBlocked": False,
                    "CreationDate": "2026-11-20",
                    "VendorIBAN": "GB29NWBK60161331926819",
                },
            ],
            "A_SalesOrder": [
                {
                    "SalesOrder": "0000501201",
                    "CompanyCode": "1000",
                    "SalesOrg": "DXB1",
                    "SoldToParty": "CUST-EMIRATES-LOG",
                    "NetAmount": 410000.00,
                    "Currency": "AED",
                    "CreditBlockStatus": "CLEAR",
                    "DeliveryStatus": "IN_TRANSIT",
                    "CustomerTaxId": "TRN-100293847500003",
                },
                {
                    "SalesOrder": "0000501202",
                    "CompanyCode": "2000",
                    "SalesOrg": "RUH1",
                    "SoldToParty": "CUST-NEOM-GRID",
                    "NetAmount": 920000.00,
                    "Currency": "SAR",
                    "CreditBlockStatus": "CREDIT_HOLD",
                    "DeliveryStatus": "BLOCKED",
                    "CustomerTaxId": "VAT-300495867100003",
                },
            ],
            "A_JournalEntryItem": [
                {
                    "AccountingDocument": "1900045101",
                    "CompanyCode": "1000",
                    "FiscalYear": 2026,
                    "GLAccount": "0000400100",
                    "CostCenter": "CC-AI-PLATFORM",
                    "DebitCreditCode": "S",
                    "AmountInCompanyCodeCurrency": 64000.00,
                    "PostingDate": "2026-11-15",
                },
                {
                    "AccountingDocument": "1900045102",
                    "CompanyCode": "1000",
                    "FiscalYear": 2026,
                    "GLAccount": "0000211000",
                    "CostCenter": "CC-AI-PLATFORM",
                    "DebitCreditCode": "H",
                    "AmountInCompanyCodeCurrency": -64000.00,
                    "PostingDate": "2026-11-15",
                },
            ],
            "A_MaterialStock": [
                {
                    "Material": "MAT-GPU-H200-NODE",
                    "CompanyCode": "1000",
                    "Plant": "DXB1",
                    "StorageLocation": "WH01",
                    "UnrestrictedStockQty": 18,
                    "SafetyStockQty": 6,
                    "BaseUnit": "EA",
                },
                {
                    "Material": "MAT-TURBINE-VALVE-9",
                    "CompanyCode": "1000",
                    "Plant": "DXB1",
                    "StorageLocation": "WH02",
                    "UnrestrictedStockQty": 3,
                    "SafetyStockQty": 10,
                    "BaseUnit": "EA",
                },
            ],
        }
    )
