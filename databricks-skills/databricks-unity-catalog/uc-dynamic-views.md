# Unity Catalog Dynamic Views

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Dynamic views provide row-level security, column-level security, and data masking by embedding identity-based logic directly into the view definition using SQL functions like `is_account_group_member()` and `session_user()`. They predate ABAC policies and are still valid for specific scenarios — particularly when security logic spans multiple source tables or requires complex reshaping.

This file covers how dynamic views work, their limitations at scale, and a structured migration path to ABAC policies for customers ready to upgrade.

## Contents

- **How Dynamic Views Work** — identity functions (`is_account_group_member`, `session_user`, `is_member`), which to use
- **SQL Patterns** — row-level security, owner-based filter, column-level security, partial masking with regex, combined row + column
- **Granting Access** — grant to view only, never to base table; why this matters
- **Compute Requirements** — SQL warehouses, standard access mode, dedicated (DBR 15.4 LTS+)
- **Limitations of Dynamic Views** — 8 limitations: object name change, no SHOW EFFECTIVE POLICIES, no EXCEPT, Delta operations bypass
- **When Dynamic Views Are Still Appropriate** — multi-table JOINs, complex reshaping, runtime < 15.4
- **Migration Path: Dynamic Views → ABAC** — 10-step process from inventory to view drop
- **Migration Considerations** — application name change, multi-table views, parallel validation

---

## How Dynamic Views Work

A dynamic view wraps a base table and uses `CASE` expressions with identity functions to filter rows or transform column values at query time. The security logic is embedded in the view SQL — callers query the view, not the base table.

### Identity Functions

| Function | Returns | Recommended For |
|----------|---------|----------------|
| `is_account_group_member('group')` | `TRUE` if caller is in the account-level group | Unity Catalog — use this |
| `session_user()` | Email of the current session user | Owner-based filtering |
| `is_member('group')` | `TRUE` if caller is in the workspace-level group | Legacy — not recommended for UC |

---

## SQL Patterns

### Row-Level Security

Filter rows based on the caller's group membership. Rows that don't satisfy the condition are invisible to the caller:

```sql
CREATE OR REPLACE VIEW <catalog>.<schema>.<view_name> AS
SELECT
  user_id,
  country,
  product,
  total
FROM <catalog>.<schema>.<base_table>
WHERE
  CASE
    WHEN is_account_group_member('managers') THEN TRUE
    ELSE total <= 1000000
  END;
```

Members of `managers` see all rows; everyone else sees only rows where `total <= 1,000,000`.

### Owner-Based Row Filter (Current User)

Each user sees only their own rows:

```sql
CREATE OR REPLACE VIEW <catalog>.<schema>.<view_name> AS
SELECT *
FROM <catalog>.<schema>.<base_table>
WHERE
  CASE
    WHEN is_account_group_member('data-admins') THEN TRUE
    ELSE owner_email = session_user()
  END;
```

### Column-Level Security

Redact a column based on group membership:

```sql
CREATE OR REPLACE VIEW <catalog>.<schema>.<view_name> AS
SELECT
  user_id,
  CASE
    WHEN is_account_group_member('auditors') THEN email
    ELSE 'REDACTED'
  END AS email,
  country,
  product,
  total
FROM <catalog>.<schema>.<base_table>;
```

### Partial Data Masking (Email Domain Only)

Expose partial values using Spark SQL functions:

```sql
CREATE OR REPLACE VIEW <catalog>.<schema>.<view_name> AS
SELECT
  user_id,
  region,
  CASE
    WHEN is_account_group_member('auditors') THEN email
    ELSE regexp_extract(email, '^.*@(.*)$', 1)
  END AS email
FROM <catalog>.<schema>.<base_table>;
```

Non-auditors see only the email domain (e.g., `databricks.com`); auditors see the full address.

### Combined Row and Column Security

```sql
CREATE OR REPLACE VIEW <catalog>.<schema>.<view_name> AS
SELECT
  user_id,
  region,
  CASE
    WHEN is_account_group_member('pii-readers') THEN ssn
    ELSE CONCAT('***-**-', RIGHT(ssn, 4))
  END AS ssn,
  CASE
    WHEN is_account_group_member('finance') THEN revenue
    ELSE NULL
  END AS revenue
FROM <catalog>.<schema>.<base_table>
WHERE
  CASE
    WHEN is_account_group_member('data-admins') THEN TRUE
    ELSE region = 'us'
  END;
```

---

## Granting Access

**Critical:** Grant users access to the view only — never to the base table directly. Direct table access bypasses the view's security logic.

```sql
-- Grant access to the view
GRANT USE CATALOG ON CATALOG <catalog> TO `<group>`;
GRANT USE SCHEMA ON SCHEMA <catalog>.<schema> TO `<group>`;
GRANT SELECT ON VIEW <catalog>.<schema>.<view_name> TO `<group>`;

-- Do NOT grant SELECT on the base table to end users
```

---

## Compute Requirements

| Compute Type | Supported |
|-------------|-----------|
| SQL Warehouses | Yes |
| Standard access mode | Yes |
| Dedicated access mode | Databricks Runtime 15.4 LTS+ |
| Dedicated Runtime ≤ 15.3 | No |

---

## Limitations of Dynamic Views

| Limitation | Impact |
|-----------|--------|
| Users query the view, not the base table | Applications must reference the view name, not the table — breaking change if you add security to an existing table |
| Security logic is embedded in view SQL | No central visibility — cannot `SHOW EFFECTIVE POLICIES` to audit who sees what |
| No `EXCEPT` clause | Exemptions for admins or pipelines must be embedded as CASE conditions in the view |
| One view per security variant | Multi-team access often requires multiple views on the same table |
| Table-level Delta operations bypass the view | CLONE, time travel, direct `SELECT` with catalog-level access all bypass the view |
| No automatic coverage for new tables | Every new table requires a manually created view |
| Complex logic in view can block optimizer | Security predicates embedded in view SQL can prevent predicate pushdown |
| No tag-based targeting | Logic must explicitly name groups and columns — brittle as the data model evolves |

---

## When Dynamic Views Are Still Appropriate

- Security logic spans **multiple source tables** (JOINs) — ABAC policies cannot span tables
- The view performs **complex reshaping** (aggregations, derived columns) alongside security filtering — keep the view for the shape, move the security to ABAC
- Organization is on Databricks Runtime **< 15.4** (dedicated) or pre-ABAC and cannot upgrade yet
- Access pattern requires **a different schema** than the base table (e.g., renaming or dropping columns)

---

## Migration Path: Dynamic Views → ABAC Policies

Use this process when upgrading customers from dynamic views to ABAC-protected base tables.

### Step 1: Inventory Existing Dynamic Views

Identify views that contain `is_account_group_member`, `is_member`, or `session_user` in their definition:

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()
WAREHOUSE_ID = "<warehouse-id>"

result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          table_catalog,
          table_schema,
          table_name AS view_name,
          view_definition
        FROM system.information_schema.views
        WHERE table_catalog = '<catalog>'
          AND (
            view_definition LIKE '%is_account_group_member%'
            OR view_definition LIKE '%is_member%'
            OR view_definition LIKE '%session_user%'
          )
        ORDER BY table_schema, table_name
    """,
)
```

### Step 2: Classify Each View's Security Logic

For each view, determine:

| Security Pattern | Migration Target |
|-----------------|----------------|
| Row filter on a single base table | ABAC row filter policy on base table |
| Column mask on a single base table | ABAC column mask policy on base table |
| Multi-table JOIN with row/column security | Split: keep view for JOIN shape, add ABAC on base tables |
| View used only for column rename / schema change | Not a security view — skip |

### Step 3: Define Governed Tags for the Security Logic

Map the view's CASE conditions to governed tag keys and values:

```sql
-- Example: view masks columns named ssn, email, dob
-- Map to governed tags
CREATE GOVERNED TAG IF NOT EXISTS pii
  VALUES ('ssn', 'email', 'dob', 'phone');

-- Example: view filters rows by region column
CREATE GOVERNED TAG IF NOT EXISTS sensitivity
  VALUES ('public', 'internal', 'confidential', 'restricted');
```

### Step 4: Apply Governed Tags to Base Tables and Columns

```python
def execute_sql(statement: str) -> None:
    w.statement_execution.execute_statement(
        warehouse_id=WAREHOUSE_ID, statement=statement
    )

# Tag the base table
execute_sql(
    "ALTER TABLE main.sales.transactions SET TAGS ('sensitivity' = 'confidential')"
)

# Tag columns that the view was masking
execute_sql(
    "ALTER TABLE main.sales.transactions ALTER COLUMN ssn SET TAGS ('pii' = 'ssn')"
)
execute_sql(
    "ALTER TABLE main.sales.transactions ALTER COLUMN email SET TAGS ('pii' = 'email')"
)
```

### Step 5: Create ABAC UDFs Matching the View's Logic

Extract the CASE logic from the view and convert it to standalone UDFs:

```sql
-- View had: CASE WHEN is_account_group_member('auditors') THEN email ELSE 'REDACTED' END
-- Becomes:
CREATE OR REPLACE FUNCTION main.security.mask_pii(val STRING)
RETURNS STRING
RETURN CASE
  WHEN is_account_group_member('auditors') THEN val
  ELSE 'REDACTED'
END;

-- View had: WHERE CASE WHEN is_account_group_member('managers') THEN TRUE ELSE region = 'us' END
-- Becomes:
CREATE OR REPLACE FUNCTION main.security.region_filter(region STRING)
RETURNS BOOLEAN
RETURN is_account_group_member('managers')
    OR region = 'us';
```

### Step 6: Create ABAC Policies on the Base Table

```python
from databricks.sdk.service.catalog import (
    ColumnMaskOptions, FunctionArgument, MatchColumn,
    PolicyInfo, PolicyType, RowFilterOptions, SecurableType,
)

# Column mask policy
w.policies.create_policy(
    PolicyInfo(
        name="mask_pii_columns",
        comment="Replaces dynamic view column masking with ABAC policy",
        on_securable_type=SecurableType.SCHEMA,
        on_securable_fullname="main.sales",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_COLUMN_MASK,
        to_principals=["account users"],
        except_principals=["auditors", "data-admins"],
        match_columns=[MatchColumn(condition="has_tag('pii')", alias="pii_col")],
        column_mask=ColumnMaskOptions(
            function_name="main.security.mask_pii",
            on_column="pii_col",
            using=[],
        ),
    )
)

# Row filter policy
w.policies.create_policy(
    PolicyInfo(
        name="region_row_filter",
        comment="Replaces dynamic view row filter with ABAC policy",
        on_securable_type=SecurableType.SCHEMA,
        on_securable_fullname="main.sales",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_ROW_FILTER,
        to_principals=["account users"],
        except_principals=["managers", "data-admins"],
        when_condition="has_tag_value('sensitivity', 'confidential')",
        match_columns=[MatchColumn(condition="has_tag('region')", alias="region_col")],
        row_filter=RowFilterOptions(
            function_name="main.security.region_filter",
            using=[FunctionArgument(alias="region_col")],
        ),
    )
)
```

### Step 7: Grant Users Direct Access to the Base Table

```sql
-- Now grant SELECT on the base table (ABAC will enforce security)
GRANT USE CATALOG ON CATALOG main TO `analysts`;
GRANT USE SCHEMA ON SCHEMA main.sales TO `analysts`;
GRANT SELECT ON TABLE main.sales.transactions TO `analysts`;
```

### Step 8: Validate Side by Side

Before dropping the view, verify ABAC policies produce identical results:

```sql
-- Check effective policies on the base table
SHOW EFFECTIVE POLICIES ON TABLE main.sales.transactions;

-- Compare results between view and base table for a test user (admin only)
EXECUTE AS USER 'analyst@example.com'
SELECT COUNT(*), SUM(total) FROM main.sales.transactions_view;

EXECUTE AS USER 'analyst@example.com'
SELECT COUNT(*), SUM(total) FROM main.sales.transactions;
```

### Step 9: Update Application References

Update any queries, notebooks, jobs, or dashboards that reference the old view name to use the base table name directly. The security is now enforced transparently on the table.

### Step 10: Drop the Security View

Only after all references are updated and validation passes:

```sql
DROP VIEW IF EXISTS main.sales.transactions_view;
```

---

## Migration Considerations

- **Applications must change object names** — migrating from a view to ABAC requires updating all consumers from `view_name` to `table_name`. This is the most disruptive part of the migration.
- **Multi-table views cannot be fully migrated** — if the view JOINs multiple tables, only the security predicate portion moves to ABAC. Keep the view for the JOIN shape; add ABAC on the base tables to enforce column-level security there.
- **Complex view logic** (aggregations, derived columns) is not a security concern — don't migrate that part. Only migrate `CASE`/`WHERE` blocks that reference `is_account_group_member()` or `session_user()`.
- **Run views and ABAC policies in parallel** during transition to validate parity before removing the view.

---

## Resources

- [Dynamic views in Databricks](https://docs.databricks.com/en/views/dynamic.html)
- [Create and manage views in Unity Catalog](https://docs.databricks.com/aws/en/data-governance/unity-catalog/create-views.html)
- [ABAC vs. row-level security and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/abac-vs-rls-cm)
- [SQL reference: CREATE VIEW](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-create-view.html)

## Related Files

- [abac-overview.md](abac-overview.md) — Full ABAC vs. dynamic views comparison
- [abac-governed-tags.md](abac-governed-tags.md) — Creating governed tags for migration Step 3
- [abac-policies.md](abac-policies.md) — Creating ABAC policies for migration Steps 5–6
- [traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md) — Traditional per-table approach and its own migration path to ABAC
- [uc-acls.md](uc-acls.md) — Granting direct table access in migration Step 7
