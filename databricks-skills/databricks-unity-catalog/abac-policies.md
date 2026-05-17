# ABAC Policies

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Complete reference for creating, editing, and managing Unity Catalog ABAC row filter and column mask policies. Policies attach to a catalog, schema, or table and are evaluated dynamically at query time based on governed tag conditions.

**Prerequisite:** Object privileges (`USE CATALOG`, `USE SCHEMA`, `SELECT`) must be granted first. See [uc-acls.md](uc-acls.md). Governed tags must exist and be applied to target tables/columns. See [abac-governed-tags.md](abac-governed-tags.md).

## Contents

- **Policy Anatomy** — `ON`, `TO`, `EXCEPT`, `WHEN`, `MATCH COLUMNS`, `ON COLUMN`, `USING COLUMNS` clauses explained
- **Full SQL Syntax** — complete `CREATE POLICY` grammar for row filters and column masks
- **Working Examples** — 5 examples: region row filter, SSN mask, block unverified tables, multi-column filter, catalog-level policy
- **Policy Management SQL** — `DROP POLICY`, `SHOW POLICIES`, `SHOW EFFECTIVE POLICIES`, `DESCRIBE POLICY`
- **Python SDK** — `w.policies.create_policy()`, `update_policy()`, `delete_policy()`, `list_policies()`, `list_effective_policies()`
- **Policy Evaluation Behavior** — query-time evaluation, immediate effect, type casting, fail-closed
- **Grant EXECUTE on Policy UDFs** — required by policy creator only; end users do not need it

---

## Policy Anatomy

Every ABAC policy has:
- **`ON`** — the securable object the policy attaches to (catalog, schema, or table)
- **`ROW FILTER` or `COLUMN MASK`** — the type of policy and the UDF to apply
- **`TO`** — principals the policy applies to
- **`EXCEPT`** (optional) — principals exempt from the policy
- **`FOR TABLES`** — signals this policy evaluates against tables within the scope
- **`WHEN`** (optional) — table-level boolean condition using `has_tag()` / `has_tag_value()`; if omitted the policy applies to all tables in scope
- **`MATCH COLUMNS`** (optional) — identifies target columns by tag condition; assigns an alias used as a UDF argument; max 3 expressions
- **`ON COLUMN`** (column masks only) — which matched column alias to mask
- **`USING COLUMNS`** (optional) — maps UDF arguments to matched column aliases or string constants

---

## Full SQL Syntax

### Row Filter Policy

```sql
CREATE [OR REPLACE] POLICY <policy_name>
ON { CATALOG <catalog> | SCHEMA <catalog>.<schema> | TABLE <catalog>.<schema>.<table> }
[COMMENT '<description>']
ROW FILTER <catalog>.<schema>.<function_name>
TO <principal> [, <principal> ...]
[EXCEPT <principal> [, <principal> ...]]
FOR TABLES
[WHEN <condition>]
[MATCH COLUMNS <condition> [AS <alias>] [, <condition> [AS <alias>] ...]]
[USING COLUMNS (<arg> [, <arg> ...])];
```

### Column Mask Policy

```sql
CREATE [OR REPLACE] POLICY <policy_name>
ON { CATALOG <catalog> | SCHEMA <catalog>.<schema> | TABLE <catalog>.<schema>.<table> }
[COMMENT '<description>']
COLUMN MASK <catalog>.<schema>.<function_name>
TO <principal> [, <principal> ...]
[EXCEPT <principal> [, <principal> ...]]
FOR TABLES
[WHEN <condition>]
[MATCH COLUMNS <condition> [AS <alias>] [, <condition> [AS <alias>] ...]]
ON COLUMN <alias>
[USING COLUMNS (<arg> [, <arg> ...])];
```

---

## Working Examples

### 1. Row Filter by Region Tag — Group Membership

Restricts rows on high-sensitivity tables to users whose group matches the row's region value. Admins are always exempt.

```sql
-- UDF: returns TRUE if caller is in the group named after the region value
CREATE OR REPLACE FUNCTION main.security.region_filter(region STRING)
RETURNS BOOLEAN
RETURN is_account_group_member(region) OR is_account_group_member('data-admins');

-- Policy: applies to tables in main.sales tagged sensitivity=high
--         that have a column tagged geo_region
CREATE POLICY hide_cross_region_rows
ON SCHEMA main.sales
COMMENT 'Restrict rows to users in the matching regional group'
ROW FILTER main.security.region_filter
TO `account users`
EXCEPT `data-admins`
FOR TABLES
WHEN has_tag_value('sensitivity', 'high')
MATCH COLUMNS has_tag('geo_region') AS region
USING COLUMNS (region);
```

### 2. Column Mask — SSN Partial Reveal with Admin Exempt

```sql
-- UDF: show full value to pii-readers, last 4 digits to everyone else
CREATE OR REPLACE FUNCTION main.security.mask_ssn(ssn STRING, show_last INT)
RETURNS STRING
DETERMINISTIC
RETURN CONCAT('***-**-', RIGHT(ssn, show_last));

-- Policy: masks all columns tagged pii=ssn; admins see full value via EXCEPT
CREATE POLICY mask_ssn_columns
ON SCHEMA main.hr
COMMENT 'Mask SSN columns for non-privileged users'
COLUMN MASK main.security.mask_ssn
TO `account users`
EXCEPT `pii-readers`, `data-admins`
FOR TABLES
MATCH COLUMNS has_tag_value('pii', 'ssn') AS ssn_col
ON COLUMN ssn_col
USING COLUMNS (4);
```

### 3. Block All Unverified / Unclassified Tables

Deny all row access to tables that have not yet been reviewed. Admins can still access them.

```sql
-- UDF: always returns FALSE (no rows visible)
CREATE OR REPLACE FUNCTION main.security.block_all()
RETURNS BOOLEAN
RETURN FALSE;

-- Policy: applies to any table tagged classification=unverified
CREATE POLICY block_unverified_tables
ON CATALOG main
COMMENT 'Block access to unreviewed tables until classification is confirmed'
ROW FILTER main.security.block_all
TO `account users`
EXCEPT `data-admins`
FOR TABLES
WHEN has_tag_value('classification', 'unverified');
```

### 4. Multi-Column Row Filter (Ship Country + Bill Country)

Uses two `MATCH COLUMNS` conditions (up to 3 are allowed):

```sql
CREATE OR REPLACE FUNCTION main.security.filter_by_countries(
  ship_country STRING,
  bill_country STRING,
  allowed_countries STRING
)
RETURNS BOOLEAN
DETERMINISTIC
RETURN array_contains(split(allowed_countries, ','), lower(ship_country))
    OR array_contains(split(allowed_countries, ','), lower(bill_country))
    OR is_account_group_member('global-analysts');

CREATE POLICY regional_orders_filter
ON SCHEMA main.orders
COMMENT 'Restrict order rows to rows matching analyst region'
ROW FILTER main.security.filter_by_countries
TO `regional-analysts`
EXCEPT `global-analysts`, `data-admins`
FOR TABLES
WHEN has_tag_value('sensitivity', 'high')
MATCH COLUMNS
  has_tag('ship_country') AS ship,
  has_tag('bill_country') AS bill
USING COLUMNS (ship, bill, 'us,ca,mx');
```

### 5. Catalog-Level Policy Covering the Entire Data Estate

```sql
CREATE POLICY catalog_pii_mask
ON CATALOG main
COMMENT 'Mask all PII columns across the entire catalog for external-analysts'
COLUMN MASK main.security.mask_pii_generic
TO `external-analysts`
FOR TABLES
MATCH COLUMNS has_tag('pii') AS pii_col
ON COLUMN pii_col
USING COLUMNS ();
```

---

## Policy Management SQL

```sql
-- Edit a policy (full replace)
CREATE OR REPLACE POLICY mask_ssn_columns
ON SCHEMA main.hr
COLUMN MASK main.security.mask_ssn
TO `account users`
EXCEPT `pii-readers`, `data-admins`, `compliance-team`
FOR TABLES
MATCH COLUMNS has_tag_value('pii', 'ssn') AS ssn_col
ON COLUMN ssn_col
USING COLUMNS (4);

-- Delete a policy
DROP POLICY mask_ssn_columns ON SCHEMA main.hr;
DROP POLICY hide_cross_region_rows ON SCHEMA main.sales;

-- List all policies on a securable
SHOW POLICIES ON SCHEMA main.hr;
SHOW POLICIES ON CATALOG main;

-- Show all effective policies (including inherited from parent)
SHOW EFFECTIVE POLICIES ON TABLE main.hr.employees;
SHOW EFFECTIVE POLICIES ON SCHEMA main.hr;

-- Describe a specific policy
DESCRIBE POLICY mask_ssn_columns ON SCHEMA main.hr;
```

---

## Python SDK

### Imports

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import (
    ColumnMaskOptions,
    FunctionArgument,
    MatchColumn,
    PolicyInfo,
    PolicyType,
    RowFilterOptions,
    SecurableType,
)

w = WorkspaceClient()
```

### Create a Row Filter Policy

```python
w.policies.create_policy(
    PolicyInfo(
        name="hide_cross_region_rows",
        comment="Restrict rows to users in the matching regional group",
        on_securable_type=SecurableType.SCHEMA,
        on_securable_fullname="main.sales",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_ROW_FILTER,
        to_principals=["account users"],
        except_principals=["data-admins"],
        when_condition="has_tag_value('sensitivity', 'high')",
        match_columns=[
            MatchColumn(condition="has_tag('geo_region')", alias="region"),
        ],
        row_filter=RowFilterOptions(
            function_name="main.security.region_filter",
            using=[FunctionArgument(alias="region")],
        ),
    )
)
```

### Create a Column Mask Policy

```python
w.policies.create_policy(
    PolicyInfo(
        name="mask_ssn_columns",
        comment="Mask SSN columns for non-privileged users",
        on_securable_type=SecurableType.SCHEMA,
        on_securable_fullname="main.hr",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_COLUMN_MASK,
        to_principals=["account users"],
        except_principals=["pii-readers", "data-admins"],
        match_columns=[
            MatchColumn(condition="has_tag_value('pii', 'ssn')", alias="ssn_col"),
        ],
        column_mask=ColumnMaskOptions(
            function_name="main.security.mask_ssn",
            on_column="ssn_col",
            using=[FunctionArgument(constant="4")],
        ),
    )
)
```

### Partial Update (Update Specific Fields)

```python
w.policies.update_policy(
    on_securable_type="SCHEMA",
    on_securable_fullname="main.hr",
    name="mask_ssn_columns",
    policy_info=PolicyInfo(
        except_principals=["pii-readers", "data-admins", "compliance-team"],
    ),
    update_mask="except_principals",
)
```

### Delete a Policy

```python
w.policies.delete_policy(
    on_securable_type="SCHEMA",
    on_securable_fullname="main.hr",
    name="mask_ssn_columns",
)
```

### List Policies on a Securable

```python
for policy in w.policies.list_policies(
    on_securable_type="SCHEMA",
    on_securable_fullname="main.hr",
):
    print(f"{policy.name} — {policy.policy_type} — TO: {policy.to_principals}")
```

### Get Effective Policies for a Table

```python
for policy in w.policies.list_effective_policies(
    on_securable_type="TABLE",
    on_securable_fullname="main.hr.employees",
):
    print(f"{policy.name} from {policy.on_securable_fullname} — {policy.policy_type}")
```

---

## Policy Evaluation Behavior

- **Evaluated at query time** against the session user's identity and group memberships
- **Immediate effect**: changes to group membership or tag assignments take effect at the next query — no cache invalidation needed
- **Automatic type casting**: column mask return values are cast to match the column's declared type (ANSI SQL rules); DBR 18.1+ supports struct → VARIANT casting
- **Fail-closed**: if a governed tag or UDF referenced in a policy is deleted, queries against affected tables fail with a clear error rather than silently bypassing the policy

---

## Grant EXECUTE on Policy UDFs

For ABAC policies, only the **policy creator** needs `EXECUTE` on the UDFs at the time `CREATE POLICY` is run. End users querying ABAC-protected tables do **not** need `EXECUTE` on the UDFs — Unity Catalog evaluates the policy on their behalf.

```sql
-- Grant to the governance team / policy creator only
GRANT EXECUTE ON FUNCTION main.security.region_filter TO `governance-team`;
GRANT EXECUTE ON FUNCTION main.security.mask_ssn TO `governance-team`;
```

```python
from databricks.sdk.service.catalog import PermissionsChange, Privilege, SecurableType

for fn in ["main.security.region_filter", "main.security.mask_ssn"]:
    w.grants.update(
        securable_type=SecurableType.FUNCTION,
        full_name=fn,
        changes=[PermissionsChange(add=[Privilege.EXECUTE], principal="governance-team")],
    )
```

> **Note:** The same rule applies to traditional row filters and column masks — the identity running the `ALTER TABLE` statement needs `EXECUTE`, not the querying users. See [traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md).

---

## Resources

- [ABAC policies](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/policies)
- [ABAC policy evaluation](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/policy-evaluation)
- [ABAC common patterns](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/common-patterns)
- [ABAC best practices](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/best-practices)
- [SQL reference: CREATE POLICY](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-create-policy.html)
- [SQL reference: SHOW POLICIES / DESCRIBE POLICY](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-aux-show-policies.html)
- [Databricks SDK for Python — Policies](https://databricks-sdk-py.readthedocs.io/en/latest/workspace/catalog/policies.html)

## Related Files

- [abac-overview.md](abac-overview.md) — Concepts, compute requirements, quotas
- [abac-governed-tags.md](abac-governed-tags.md) — Creating governed tags used in `WHEN` and `MATCH COLUMNS`
- [traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md) — Per-table approach and migration path
- [abac-data-classification.md](abac-data-classification.md) — Using AI classification results to build `MATCH COLUMNS` conditions
- [abac-patterns.md](abac-patterns.md) — Reusable UDF recipes and end-to-end patterns
- [uc-acls.md](uc-acls.md) — GRANT EXECUTE on policy UDFs
