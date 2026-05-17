# Traditional Row Filters & Column Masks

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Per-table row filters and column masks are the original Unity Catalog approach to fine-grained access control. They attach SQL UDFs directly to individual tables and columns via `ALTER TABLE`. This file covers how they work, their limitations at scale, and a structured migration path to ABAC policies for customers ready to upgrade.

## Contents

- **How It Works** — row filters (BOOLEAN UDF) and column masks (transform UDF) overview
- **SQL — Row Filters** — create UDF, attach with `SET ROW FILTER`, remove with `DROP ROW FILTER`
- **SQL — Column Masks** — create UDF, attach with `ALTER COLUMN SET MASK`, remove with `DROP MASK`
- **SQL — Inspect Existing Filters and Masks** — query `information_schema.row_filters` / `column_masks`
- **Python SDK — Row Filters** — apply, remove, inspect via `w.tables.update()`
- **Python SDK — Column Masks** — apply, remove, list masked columns via `w.tables.update()`
- **Granting EXECUTE on Filter/Mask UDFs** — required by the creator, not by querying users
- **Testing a Filter or Mask** — `EXECUTE AS USER`, identity function verification
- **Limitations at Scale** — 8 limitations: per-table config, no auto-coverage, table owner bypass, no EXCEPT
- **When Traditional Filters Are Still Appropriate** — unique logic, small stable estates, runtime < 16.4
- **Migration Path: Traditional Filters → ABAC** — 7-step process from audit to UDF cleanup
- **Migration Considerations** — change windows, tag coverage, runtime requirements, coexistence during transition

---

## How It Works

### Row Filters

A row filter is a SQL UDF that returns `BOOLEAN`. It is attached to a table and evaluated silently for every query. Rows where the function returns `FALSE` are excluded from results — the caller never knows the rows exist.

### Column Masks

A column mask is a SQL UDF that transforms a column's value before it reaches the caller. The original column value is passed as an argument; the return value is what the caller sees.

Both types use identity functions (`current_user()`, `is_account_group_member()`) to make the logic dynamic based on who is running the query.

---

## SQL — Row Filters

### Create and Attach a Row Filter

```sql
-- Step 1: Create the filter UDF
CREATE OR REPLACE FUNCTION <catalog>.<schema>.region_filter(region STRING)
RETURNS BOOLEAN
RETURN is_account_group_member(region) OR is_account_group_member('data-admins');

-- Step 2: Attach to table
ALTER TABLE <catalog>.<schema>.<table>
SET ROW FILTER <catalog>.<schema>.region_filter ON (<region_column>);
```

### Current-User Row Filter

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.owner_filter(owner_col STRING)
RETURNS BOOLEAN
RETURN owner_col = current_user() OR is_account_group_member('data-admins');

ALTER TABLE <catalog>.<schema>.<table>
SET ROW FILTER <catalog>.<schema>.owner_filter ON (owner);
```

### Multi-Column Row Filter

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.region_dept_filter(
  region STRING,
  dept STRING
)
RETURNS BOOLEAN
RETURN (
  is_account_group_member(CONCAT('region-', region))
  AND is_account_group_member(CONCAT('dept-', dept))
) OR is_account_group_member('data-admins');

ALTER TABLE <catalog>.<schema>.<table>
SET ROW FILTER <catalog>.<schema>.region_dept_filter ON (region, department);
```

### Remove a Row Filter

```sql
ALTER TABLE <catalog>.<schema>.<table> DROP ROW FILTER;
```

---

## SQL — Column Masks

### Redact a Column for Non-Privileged Users

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_ssn(ssn STRING)
RETURNS STRING
RETURN CASE
  WHEN is_account_group_member('pii-readers') THEN ssn
  ELSE CONCAT('***-**-', RIGHT(ssn, 4))
END;

ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN ssn SET MASK <catalog>.<schema>.mask_ssn;
```

### Null Column for Non-Privileged Users

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_salary(salary DOUBLE)
RETURNS DOUBLE
RETURN CASE
  WHEN is_account_group_member('hr-managers') THEN salary
  ELSE NULL
END;

ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN salary SET MASK <catalog>.<schema>.mask_salary;
```

### Remove a Column Mask

```sql
ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN <column> DROP MASK;
```

---

## SQL — Inspect Existing Filters and Masks

```sql
-- List all row filters in a catalog
SELECT table_catalog, table_schema, table_name, row_filter_name, row_filter_arg_names
FROM system.information_schema.row_filters
WHERE table_catalog = '<catalog>';

-- List all column masks in a catalog
SELECT table_catalog, table_schema, table_name, column_name, mask_name
FROM system.information_schema.column_masks
WHERE table_catalog = '<catalog>';

-- Inspect filter/mask on a specific table
DESCRIBE EXTENDED <catalog>.<schema>.<table>;
```

---

## Python SDK — Row Filters

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import RowFilter

w = WorkspaceClient()

# Apply row filter
w.tables.update(
    full_name="main.sales.transactions",
    row_filter=RowFilter(
        function_name="main.security.region_filter",
        input_column_names=["region"],
    ),
)

# Remove row filter
w.tables.update(
    full_name="main.sales.transactions",
    row_filter=None,
)

# Check if a row filter is set
table = w.tables.get("main.sales.transactions")
if table.row_filter:
    print(f"Filter: {table.row_filter.function_name}")
    print(f"Columns: {table.row_filter.input_column_names}")
```

---

## Python SDK — Column Masks

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import ColumnMask

w = WorkspaceClient()

# Apply column mask
table = w.tables.get("main.hr.employees")
for col in table.columns or []:
    if col.name == "ssn":
        col.mask = ColumnMask(
            function_name="main.security.mask_ssn",
            using_column_names=[],
        )

w.tables.update(full_name="main.hr.employees", columns=table.columns)

# Remove column mask
table = w.tables.get("main.hr.employees")
for col in table.columns or []:
    if col.name == "ssn":
        col.mask = None

w.tables.update(full_name="main.hr.employees", columns=table.columns)

# List all masked columns
table = w.tables.get("main.hr.employees")
for col in table.columns or []:
    if col.mask:
        print(f"Column: {col.name}, Mask: {col.mask.function_name}")
```

---

## Granting EXECUTE on Filter/Mask UDFs

The identity running `ALTER TABLE SET ROW FILTER` or `ALTER TABLE ALTER COLUMN SET MASK` must have `EXECUTE` on the UDF. End users querying the table do **not** need `EXECUTE`.

```sql
GRANT EXECUTE ON FUNCTION <catalog>.<schema>.<function> TO `<group>`;
```

```python
from databricks.sdk.service.catalog import PermissionsChange, Privilege, SecurableType

w.grants.update(
    securable_type=SecurableType.FUNCTION,
    full_name="main.security.mask_ssn",
    changes=[PermissionsChange(add=[Privilege.EXECUTE], principal="analysts")],
)
```

---

## Testing a Filter or Mask

```sql
-- Simulate query as another user (admin only)
EXECUTE AS USER 'user@example.com'
SELECT * FROM <catalog>.<schema>.<table> LIMIT 10;

-- Verify current identity
SELECT current_user();
SELECT is_account_group_member('pii-readers');
```

---

## Limitations at Scale

| Limitation | Impact |
|-----------|--------|
| Per-table configuration | Every new table must be manually configured |
| No automatic coverage | Tables added to a schema are not protected by default |
| Table owners can remove their own filters | No central enforcement guarantee |
| No `EXCEPT` clause | Exemptions for admins or pipelines must be embedded in UDF logic — harder to maintain |
| No `SHOW EFFECTIVE POLICIES` | No single view of "what policies apply to me" |
| UDF count grows linearly with tables | Hundreds of near-identical functions become unmaintainable |
| No tag-driven targeting | Column must be statically named at attachment time |

---

## When Traditional Filters Are Still Appropriate

- Table has unique, non-generalizable filter logic that doesn't apply to any other table
- Table owner should own and manage their own protection directly
- Small, stable set of tables (fewer than ~20) that change infrequently
- Organization is on Databricks Runtime < 16.4 and cannot yet use ABAC

---

## Migration Path: Traditional Filters → ABAC

Use this process when upgrading customers from per-table filters to ABAC policies.

### Step 1: Audit All Existing Filters and Masks

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

# Inventory row filters
result = w.statement_execution.execute_statement(
    warehouse_id="<warehouse-id>",
    statement="""
        SELECT table_catalog, table_schema, table_name,
               row_filter_name, row_filter_arg_names
        FROM system.information_schema.row_filters
        WHERE table_catalog = '<catalog>'
        ORDER BY table_schema, table_name
    """,
)

# Inventory column masks
result = w.statement_execution.execute_statement(
    warehouse_id="<warehouse-id>",
    statement="""
        SELECT table_catalog, table_schema, table_name,
               column_name, mask_name
        FROM system.information_schema.column_masks
        WHERE table_catalog = '<catalog>'
        ORDER BY table_schema, table_name, column_name
    """,
)
```

### Step 2: Define a Governed Tag Taxonomy

Map existing column names and filter logic to governed tag keys and values:

| Existing Pattern | Governed Tag |
|-----------------|-------------|
| Column named `ssn` with mask | `pii = 'ssn'` |
| Column named `email` with mask | `pii = 'email'` |
| Tables with `region`-based filter | Table tag `sensitivity = 'high'` + column tag `has_tag('region')` |
| Tables with owner-based filter | Table tag `access_mode = 'owner-only'` |

```sql
CREATE GOVERNED TAG pii VALUES ('ssn', 'ccn', 'dob', 'email', 'phone');
CREATE GOVERNED TAG sensitivity VALUES ('public', 'internal', 'confidential', 'restricted');
```

### Step 3: Apply Governed Tags to Tables and Columns

```python
def execute_sql(warehouse_id: str, statement: str) -> None:
    w.statement_execution.execute_statement(
        warehouse_id=warehouse_id, statement=statement
    )

WAREHOUSE_ID = "<warehouse-id>"

# Tag tables
execute_sql(WAREHOUSE_ID,
    "ALTER TABLE main.hr.employees SET TAGS ('sensitivity' = 'confidential')")

# Tag columns
execute_sql(WAREHOUSE_ID,
    "ALTER TABLE main.hr.employees ALTER COLUMN ssn SET TAGS ('pii' = 'ssn')")
execute_sql(WAREHOUSE_ID,
    "ALTER TABLE main.hr.employees ALTER COLUMN email SET TAGS ('pii' = 'email')")
```

### Step 4: Create the ABAC Policy at Schema Level

```sql
-- Create the UDF (can reuse existing UDF if logic is the same)
CREATE OR REPLACE FUNCTION main.security.mask_pii(val STRING, show_last INT)
RETURNS STRING
DETERMINISTIC
RETURN CASE
  WHEN is_account_group_member('pii-readers') THEN val
  ELSE CONCAT('***', RIGHT(val, show_last))
END;

-- Create ABAC column mask policy covering all pii=ssn columns in the schema
CREATE POLICY mask_pii_columns
ON SCHEMA main.hr
COMMENT 'Mask all PII columns for non-pii-readers'
COLUMN MASK main.security.mask_pii
TO `account users` EXCEPT `pii-readers`, `data-admins`
FOR TABLES
MATCH COLUMNS has_tag('pii') AS pii_col
ON COLUMN pii_col
USING COLUMNS (4);
```

### Step 5: Validate Side-by-Side

Before removing old filters, verify the ABAC policy produces the same results:

```sql
-- Check effective policies on the table
SHOW EFFECTIVE POLICIES ON TABLE main.hr.employees;

-- Test as a non-privileged user (admin only)
EXECUTE AS USER 'analyst@example.com'
SELECT ssn, email FROM main.hr.employees LIMIT 5;
```

### Step 6: Remove Old Table-Level Filters and Masks

Only after validation passes:

```sql
ALTER TABLE main.hr.employees ALTER COLUMN ssn DROP MASK;
ALTER TABLE main.hr.employees ALTER COLUMN email DROP MASK;
```

```python
# Or via SDK
table = w.tables.get("main.hr.employees")
for col in table.columns or []:
    if col.name in ("ssn", "email"):
        col.mask = None
w.tables.update(full_name="main.hr.employees", columns=table.columns)
```

### Step 7: Clean Up Standalone UDFs

Only remove UDFs that are no longer referenced by any filter, mask, or ABAC policy:

```sql
DROP FUNCTION IF EXISTS main.security.old_ssn_mask;
DROP FUNCTION IF EXISTS main.security.old_email_mask;
```

---

## Migration Considerations

- **Change window**: Table owners can modify or remove their own filters at any time. Coordinate the migration under a change window to prevent gaps
- **Tag coverage verification**: An ABAC policy on a schema applies to ALL tables with matching tags — confirm every table is correctly tagged before removing old filters
- **Runtime version**: ABAC requires DBR 16.4+. Keep traditional filters on any tables accessed from older runtimes until those clusters are upgraded
- **Combining during transition**: Old table-level filters and new ABAC policies can coexist temporarily. Both will apply; be aware of the conflict rule (one filter per user per table — if both resolve to the same user, access is blocked)

---

## Resources

- [Row filters and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/row-and-column-filters.html)
- [ABAC vs. row-level security and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/abac-vs-rls-cm)
- [Databricks SDK for Python — Tables](https://databricks-sdk-py.readthedocs.io/en/latest/workspace/catalog/tables.html)

## Related Files

- [abac-overview.md](abac-overview.md) — Full comparison of traditional vs. ABAC approach
- [abac-governed-tags.md](abac-governed-tags.md) — Creating the governed tag taxonomy needed for migration Step 2
- [abac-policies.md](abac-policies.md) — Complete ABAC policy syntax and SDK usage
- [uc-acls.md](uc-acls.md) — GRANT EXECUTE on filter/mask UDFs
