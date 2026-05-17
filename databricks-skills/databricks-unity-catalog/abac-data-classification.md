# Data Classification

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Data Classification is an AI-powered feature that automatically scans Unity Catalog tables to detect sensitive data and applies system-generated `class.*` governed tags to identified columns. It is the discovery layer that feeds recommendations into ABAC policy design — Classification identifies *what* is sensitive, Governed Tags *label* it, and ABAC Policies *enforce* access based on those labels.

**Status:** Public Preview (workspace admin must enable). Auto-tagging: Beta. Custom classifiers: Beta.

## Contents

- **How It Works** — AI background scanning, results in `system.data_classification.results`, auto-tagging flow
- **System Classification Tags** — global `class.*` tags, US, UK, Germany, Australia, Brazil regional tags
- **Compliance Framework Mappings** — GDPR, HIPAA, GLBA, PCI DSS, DPDPA coverage
- **Required Permissions** — enable classification, enable auto-tagging, view results, view sample values
- **Querying Classification Results** — high-confidence detections, deduplicated most-recent results, summary by schema
- **Cost Monitoring** — DBU usage query via `system.billing.usage`
- **Classification → ABAC Policy Workflow** — 4-step end-to-end: query results → map tags → apply tags → create policy
- **Using System Class Tags Directly in ABAC Policies** — use `class.*` tags in `MATCH COLUMNS` without a custom taxonomy
- **Limitations** — views not supported, 24-hour scan delay, auto-tagging backfill timing

---

## How It Works

1. Classification runs as a background job using serverless compute
2. It samples column values and uses ML models to detect sensitive data types
3. Detection results are stored in `system.data_classification.results`
4. Optionally, high-confidence detections can automatically apply `class.*` system governed tags to columns (auto-tagging)
5. Those tags can then be used directly in `MATCH COLUMNS has_tag('class.us_ssn')` clauses in ABAC column mask policies

---

## System Classification Tags

These tags are created and managed by Databricks. They cannot be modified.

### Global (All Regions)

| Tag | Data Type Detected |
|-----|-------------------|
| `class.name` | Personal name |
| `class.email_address` | Email address |
| `class.phone_number` | Phone number |
| `class.ip_address` | IP address |
| `class.location` | Physical location / address |
| `class.url` | URL |
| `class.credit_card` | Credit card number |
| `class.iban_code` | IBAN bank account number |
| `class.vin` | Vehicle identification number |
| `class.date_of_birth` | Date of birth |
| `class.age` | Age |
| `class.driver_license` | Driver's license number (generic) |
| `class.passport` | Passport number (generic) |
| `class.license_plate` | License plate number |

### United States

| Tag | Data Type Detected |
|-----|-------------------|
| `class.us_ssn` | US Social Security Number |
| `class.us_itin` | US Individual Taxpayer Identification Number |
| `class.us_bank_number` | US bank account number |
| `class.us_driver_license` | US state driver's license |
| `class.us_passport` | US passport number |

### United Kingdom (EU Regions Only)

| Tag | Data Type Detected |
|-----|-------------------|
| `class.uk_nhs` | UK National Health Service number |
| `class.uk_nino` | UK National Insurance number |

### Germany (EU Regions Only)

| Tag | Data Type Detected |
|-----|-------------------|
| `class.de_id_card` | German ID card number |
| `class.de_svnr` | German social security number |
| `class.de_tax_id` | German tax identification number |

### Australia

| Tag | Data Type Detected |
|-----|-------------------|
| `class.au_medicare` | Australian Medicare number |
| `class.au_tfn` | Australian Tax File Number |

### Brazil

| Tag | Data Type Detected |
|-----|-------------------|
| `class.br_cpf` | Brazilian CPF (individual taxpayer registry) |
| `class.br_rg` | Brazilian RG (general registry) |
| `class.br_cnpj` | Brazilian CNPJ (company tax ID) |

---

## Compliance Framework Mappings

| Framework | Key `class.*` Tags Covered |
|-----------|--------------------------|
| GDPR | `class.name`, `class.email_address`, `class.phone_number`, `class.date_of_birth`, `class.ip_address`, `class.location` |
| HIPAA | `class.name`, `class.date_of_birth`, `class.us_ssn`, `class.phone_number`, `class.email_address` |
| GLBA | `class.us_ssn`, `class.us_bank_number`, `class.credit_card` |
| PCI DSS | `class.credit_card`, `class.us_bank_number` |
| DPDPA | `class.name`, `class.email_address`, `class.phone_number`, `class.date_of_birth` |

---

## Required Permissions

| Action | Permissions Required |
|--------|---------------------|
| Enable classification on a catalog | `USE CATALOG` + `MANAGE` on catalog |
| Enable auto-tagging | `USE CATALOG` + `APPLY TAG` on catalog + `ASSIGN` on `class.*` tags |
| View classification results | `USE CATALOG` + (`MANAGE` or `SELECT` + `USE SCHEMA`) |
| View sample column values in results | `SELECT` on `system.data_classification.results` |

---

## Querying Classification Results

### Get All High-Confidence PII Detections in a Catalog

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()
WAREHOUSE_ID = "<warehouse-id>"

result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          catalog_name,
          schema_name,
          table_name,
          column_name,
          class_name,
          score,
          scan_timestamp
        FROM system.data_classification.results
        WHERE catalog_name = '<catalog>'
          AND score >= 0.8
        ORDER BY schema_name, table_name, column_name, score DESC
    """,
)
```

### Get Most Recent Result per Column (Deduplicated)

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        WITH ranked AS (
          SELECT
            catalog_name,
            schema_name,
            table_name,
            column_name,
            class_name,
            score,
            scan_timestamp,
            ROW_NUMBER() OVER (
              PARTITION BY catalog_name, schema_name, table_name, column_name, class_name
              ORDER BY scan_timestamp DESC
            ) AS rn
          FROM system.data_classification.results
          WHERE catalog_name = '<catalog>'
        )
        SELECT catalog_name, schema_name, table_name, column_name, class_name, score
        FROM ranked
        WHERE rn = 1
          AND score >= 0.8
        ORDER BY schema_name, table_name, column_name
    """,
)
```

### Summarize PII Exposure by Schema

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          schema_name,
          class_name,
          COUNT(DISTINCT table_name) AS tables_affected,
          COUNT(DISTINCT column_name) AS columns_affected
        FROM system.data_classification.results
        WHERE catalog_name = '<catalog>'
          AND score >= 0.8
        GROUP BY schema_name, class_name
        ORDER BY schema_name, tables_affected DESC
    """,
)
```

---

## Cost Monitoring

Classification uses serverless compute and is billed as DBU consumption:

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          usage_date,
          identity_metadata.created_by,
          usage_metadata.catalog_id,
          SUM(usage_quantity) AS dbus
        FROM system.billing.usage
        WHERE billing_origin_product = 'DATA_CLASSIFICATION'
          AND usage_date >= DATE_SUB(CURRENT_DATE(), 30)
        GROUP BY usage_date, created_by, catalog_id
        ORDER BY usage_date DESC, dbus DESC
    """,
)
```

---

## Classification → ABAC Policy Workflow

This is the core use case for data classification in an ABAC implementation. Classification finds sensitive columns; you apply governed tags; ABAC policies automatically protect them.

### Step 1: Query Classification Results for High-Confidence PII

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT DISTINCT
          catalog_name,
          schema_name,
          table_name,
          column_name,
          class_name
        FROM system.data_classification.results
        WHERE catalog_name = 'main'
          AND score >= 0.85
          AND class_name IN (
            'class.us_ssn', 'class.credit_card', 'class.email_address',
            'class.date_of_birth', 'class.phone_number'
          )
        ORDER BY schema_name, table_name
    """,
)
```

### Step 2: Map Class Tags to Your Governed Tag Taxonomy

```python
CLASS_TO_GOVERNED_TAG = {
    "class.us_ssn": ("pii", "ssn"),
    "class.credit_card": ("pii", "ccn"),
    "class.email_address": ("pii", "email"),
    "class.date_of_birth": ("pii", "dob"),
    "class.phone_number": ("pii", "phone"),
    "class.name": ("pii", "name"),
}
```

### Step 3: Apply Governed Tags to Identified Columns

```python
def apply_governed_tag(
    warehouse_id: str,
    table_full_name: str,
    column: str,
    tag_key: str,
    tag_value: str,
) -> None:
    w.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=f"""
            ALTER TABLE {table_full_name}
            ALTER COLUMN {column}
            SET TAGS ('{tag_key}' = '{tag_value}')
        """,
    )

# Apply tags based on classification results
for row in result.result.data_array or []:
    catalog, schema, table, column, class_name = row
    if class_name in CLASS_TO_GOVERNED_TAG:
        tag_key, tag_value = CLASS_TO_GOVERNED_TAG[class_name]
        table_full_name = f"{catalog}.{schema}.{table}"
        apply_governed_tag(WAREHOUSE_ID, table_full_name, column, tag_key, tag_value)
        print(f"Tagged {table_full_name}.{column} → {tag_key}={tag_value}")
```

### Step 4: Create ABAC Column Mask Policies Using the Tags

With governed tags in place, a single policy covers every tagged column across the schema — including new tables added in the future:

```python
# Ensure the mask UDF exists
w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        CREATE OR REPLACE FUNCTION main.security.mask_pii(val STRING)
        RETURNS STRING
        RETURN CASE
          WHEN is_account_group_member('pii-readers') THEN val
          ELSE '***REDACTED***'
        END
    """,
)

# Create ABAC policy covering all pii-tagged columns in the schema
w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        CREATE OR REPLACE POLICY mask_all_pii
        ON SCHEMA main.hr
        COMMENT 'Mask all PII columns detected and tagged by Data Classification'
        COLUMN MASK main.security.mask_pii
        TO `account users`
        EXCEPT `pii-readers`, `data-admins`
        FOR TABLES
        MATCH COLUMNS has_tag('pii') AS pii_col
        ON COLUMN pii_col
        USING COLUMNS ()
    """,
)
```

Now any column that classification tags in the future — and that auto-tagging maps to `pii` — is automatically masked by this policy without any additional configuration.

---

## Using System Class Tags Directly in ABAC Policies

You can also use `class.*` system tags directly in ABAC policies, bypassing your governed tag taxonomy:

```sql
-- Mask any column that classification has tagged as a US SSN
CREATE POLICY mask_us_ssn_direct
ON CATALOG main
COLUMN MASK main.security.mask_ssn
TO `account users`
EXCEPT `pii-readers`
FOR TABLES
MATCH COLUMNS has_tag('class.us_ssn') AS ssn_col
ON COLUMN ssn_col
USING COLUMNS (4);
```

This approach is faster to set up but gives you less control over the tag taxonomy. Use your own governed tags when you want consistent naming and the ability to cover patterns that classification doesn't detect.

---

## Limitations

- Views and metric views are not supported — classify the underlying base tables instead
- New tables and columns are scanned within 24 hours of being added — classification is not real-time
- When auto-tagging is first enabled, existing columns are not immediately backfilled — wait for the first scan cycle to complete
- Custom classifiers (Beta) allow you to define patterns for organization-specific sensitive data types not covered by default `class.*` tags

---

## Resources

- [Data classification overview](https://docs.databricks.com/aws/en/data-governance/unity-catalog/data-classification)
- [Data classification tags reference](https://docs.databricks.com/aws/en/data-governance/unity-catalog/data-classification-tags)
- [system.data_classification.results](https://docs.databricks.com/aws/en/administration-guide/system-tables/data-classification.html)
- [Blog: ABAC, row filtering, column masking, governed tags, and data classification are now GA](https://www.databricks.com/blog/abac-row-filtering-and-column-masking-policies-governed-tags-and-data-classification-are-now)

## Related Files

- [abac-governed-tags.md](abac-governed-tags.md) — Managing the governed tag taxonomy that classification results feed into
- [abac-policies.md](abac-policies.md) — Using `has_tag('class.*')` or custom tags in `MATCH COLUMNS` conditions
- [abac-patterns.md](abac-patterns.md) — End-to-end patterns including classification-driven policy setup
