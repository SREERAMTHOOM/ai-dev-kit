# ABAC Patterns — UDF Recipes & End-to-End Workflows

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Reusable UDF patterns, complete end-to-end implementation walkthroughs, and audit query templates for Unity Catalog ABAC.

## Contents

- **UDF Design Principles** — 7 rules: SQL UDFs, DETERMINISTIC, column-only predicates, safe functions, small lookup tables, avoid non-deterministic, test at scale
- **Row Filter UDF Patterns** — identity-based, column predicate with partition pruning, current-user ownership, lookup table ACL, multi-group admin bypass
- **Column Mask UDF Patterns** — SSN partial reveal, email domain mask, salary/revenue null, generic redaction, numeric VARIANT mask, pseudonymization, struct field-level mask
- **SecureView Barrier and Predicate Pushdown** — what predicates push through vs. get blocked; how to write pushdown-friendly filters
- **End-to-End Recipe 1: Schema-Wide PII Protection** — governed tags → column tags → mask UDF → ABAC policy → verify
- **End-to-End Recipe 2: Default-Deny for Unclassified Tables** — classification tag → block-all UDF → catalog policy → promotion workflow
- **Audit Queries** — policy changes, tag assignment/removal events, table access via `system.access.audit`
- **Performance Testing Template** — 1M-row benchmark pattern

---

## UDF Design Principles

1. **Use SQL UDFs** — significantly faster than Python UDFs; SQL UDFs run inside the query engine without serialization overhead
2. **Mark as `DETERMINISTIC`** when the output depends only on inputs and not on session state — enables caching and optimizer reuse
3. **Reference only columns from the target table** — external lookups can prevent partition pruning; keep the filter predicate pushdown-friendly
4. **Use safe arithmetic functions** — `try_cast`, `try_divide`, `try_to_number` prevent runtime errors from nulls or bad data
5. **Keep lookup tables small** — if you must join to an ACL table, keep it small enough to broadcast
6. **Avoid non-deterministic functions** — `rand()`, `now()`, `uuid()` prevent the optimizer from caching results
7. **Test on at least 1 million rows** before deploying to production to catch performance regressions early

---

## Row Filter UDF Patterns

### Identity-Based (Fastest — No Column Argument)

When the filter decision is purely based on who is querying, not on row content:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.group_only_filter()
RETURNS BOOLEAN
RETURN
  CASE
    WHEN is_account_group_member('trusted-analysts') THEN TRUE
    WHEN is_account_group_member('data-admins') THEN TRUE
    ELSE FALSE
  END;
```

### Column-Based Predicate (Enables Partition Pruning)

When the filter is on a column value — use `DETERMINISTIC` to allow the optimizer to push the predicate down:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.filter_by_region(
  region STRING,
  allowed_regions STRING
)
RETURNS BOOLEAN
DETERMINISTIC
RETURN array_contains(split(allowed_regions, ','), lower(region))
    OR is_account_group_member('global-access');
```

### Current-User Row Ownership

Each user sees only their own rows, plus admins see everything:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.owner_filter(owner_email STRING)
RETURNS BOOLEAN
RETURN owner_email = current_user()
    OR is_account_group_member('data-admins');
```

### Lookup Table Access Control

When access rules are stored in a Delta table (keep the ACL table small for broadcast):

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.priority_allowed(o_priority STRING)
RETURNS BOOLEAN
RETURN EXISTS (
  SELECT 1 FROM <catalog>.<schema>.access_rules
  WHERE principal = current_user()
    AND priority = o_priority
);
```

### Multi-Group Admin Bypass (Standard Pattern)

The most common pattern — group matching with an admin escape hatch:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.regional_filter(region STRING)
RETURNS BOOLEAN
RETURN is_account_group_member(CONCAT('region-', region))
    OR is_account_group_member('data-admins');
```

---

## Column Mask UDF Patterns

### Partial Reveal — SSN Last 4 Digits

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_ssn(ssn STRING, show_last INT)
RETURNS STRING
DETERMINISTIC
RETURN CONCAT('***-**-', RIGHT(ssn, show_last));
```

Usage in policy: `USING COLUMNS (4)` passes `4` as the `show_last` argument.

### Email Partial Mask

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_email(email STRING)
RETURNS STRING
RETURN CASE
  WHEN is_account_group_member('pii-readers') THEN email
  ELSE CONCAT(LEFT(email, 1), '***@', SPLIT_PART(email, '@', 2))
END;
```

### Null for Non-Privileged Users (Salary / Revenue)

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_salary(salary DOUBLE)
RETURNS DOUBLE
RETURN CASE
  WHEN is_account_group_member('hr-managers') OR
       is_account_group_member('finance-analysts') THEN salary
  ELSE NULL
END;
```

### Generic Redaction

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.redact(val STRING)
RETURNS STRING
RETURN CASE
  WHEN is_account_group_member('pii-readers') THEN val
  ELSE '***REDACTED***'
END;
```

### Numeric VARIANT Mask (Handles INT, DOUBLE, DECIMAL with One Function)

When multiple numeric column types need the same mask, VARIANT avoids writing one UDF per type. Requires DBR 18.1+:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_numeric(val VARIANT)
RETURNS VARIANT
DETERMINISTIC
RETURN CASE
  WHEN is_account_group_member('finance-analysts') THEN val
  ELSE 0::VARIANT
END;
```

### Deterministic Pseudonymization (Consistent Hash for Analytics)

Replaces PII with a consistent pseudonym — same input always produces the same output, so joins and aggregations still work:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.pseudonymize(val STRING, version INT)
RETURNS STRING
DETERMINISTIC
RETURN SHA2(CONCAT(val, CAST(version AS STRING)), 256);
```

Usage in policy: `USING COLUMNS (1)` passes version `1`. Increment the version when you need to re-key all pseudonyms.

### Struct Column Masking with Field-Level Control

For columns that store nested structs — mask individual fields:

```sql
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_contact_struct(data VARIANT)
RETURNS VARIANT
RETURN CASE
  WHEN is_account_group_member('pii-readers') THEN data
  ELSE to_variant_object(named_struct(
    'name', 'REDACTED',
    'email', CONCAT(LEFT(data:email::STRING, 1), '***@', SPLIT_PART(data:email::STRING, '@', 2)),
    'phone', '***-***-****'
  ))
END;
```

---

## SecureView Barrier and Predicate Pushdown

ABAC policies wrap tables in a secure view at execution time. This can affect whether the query optimizer pushes predicates through to the underlying storage:

| Predicate Type | Pushed Through | Example |
|---------------|---------------|---------|
| Simple equality | Yes | `WHERE region = 'us'` |
| Range comparison | Yes | `WHERE created_date >= '2024-01-01'` |
| IN list | Yes | `WHERE country IN ('us', 'ca')` |
| Function call on column | **No** | `WHERE date_format(col, 'yyyy-MM-dd') = '2024-01-01'` |
| UDF call | **No** | `WHERE my_udf(col) = 'value'` |

**Recommendation:** Push date/time comparisons using direct column comparisons, not function-wrapped expressions, to avoid full table scans on date-partitioned tables.

---

## End-to-End Recipe 1: Schema-Wide PII Protection

### Scenario
You have a `main.hr` schema with employee tables. Any column tagged `pii` should be masked for all users except `pii-readers` and `data-admins`.

### Step 1: Create Governed Tags

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()
WAREHOUSE_ID = "<warehouse-id>"

def execute_sql(statement: str) -> None:
    w.statement_execution.execute_statement(
        warehouse_id=WAREHOUSE_ID, statement=statement
    )

execute_sql("""
    CREATE GOVERNED TAG IF NOT EXISTS pii
      DESCRIPTION 'Type of PII in the column'
      VALUES ('ssn', 'ccn', 'dob', 'email', 'phone', 'name')
""")

execute_sql("""
    CREATE GOVERNED TAG IF NOT EXISTS sensitivity
      DESCRIPTION 'Data sensitivity level'
      VALUES ('public', 'internal', 'confidential', 'restricted')
""")
```

### Step 2: Tag Tables and Columns

```python
# Tag table-level sensitivity
execute_sql(
    "ALTER TABLE main.hr.employees SET TAGS ('sensitivity' = 'confidential')"
)

# Tag PII columns
for column, pii_type in [
    ("ssn", "ssn"),
    ("email", "email"),
    ("date_of_birth", "dob"),
    ("phone", "phone"),
]:
    execute_sql(f"""
        ALTER TABLE main.hr.employees
        ALTER COLUMN {column}
        SET TAGS ('pii' = '{pii_type}')
    """)
```

### Step 3: Create the Mask UDF

```python
execute_sql("""
    CREATE OR REPLACE FUNCTION main.security.mask_pii(val STRING)
    RETURNS STRING
    RETURN CASE
      WHEN is_account_group_member('pii-readers') THEN val
      ELSE '***REDACTED***'
    END
""")
```

### Step 4: Grant EXECUTE on the UDF to the Policy Creator

For ABAC, only the identity running `CREATE POLICY` needs `EXECUTE` on the UDF. End users querying the protected tables do **not** need it.

```python
from databricks.sdk.service.catalog import PermissionsChange, Privilege, SecurableType

w.grants.update(
    securable_type=SecurableType.FUNCTION,
    full_name="main.security.mask_pii",
    changes=[
        PermissionsChange(add=[Privilege.EXECUTE], principal="governance-team")
    ],
)
```

### Step 5: Create the ABAC Policy

```python
from databricks.sdk.service.catalog import (
    ColumnMaskOptions, FunctionArgument, MatchColumn,
    PolicyInfo, PolicyType, SecurableType,
)

w.policies.create_policy(
    PolicyInfo(
        name="mask_all_pii_columns",
        comment="Mask all PII-tagged columns in main.hr for non-privileged users",
        on_securable_type=SecurableType.SCHEMA,
        on_securable_fullname="main.hr",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_COLUMN_MASK,
        to_principals=["account users"],
        except_principals=["pii-readers", "data-admins"],
        match_columns=[
            MatchColumn(condition="has_tag('pii')", alias="pii_col"),
        ],
        column_mask=ColumnMaskOptions(
            function_name="main.security.mask_pii",
            on_column="pii_col",
            using=[],
        ),
    )
)
```

### Step 6: Verify

```python
execute_sql("SHOW EFFECTIVE POLICIES ON TABLE main.hr.employees")
```

Any new table added to `main.hr` that has a `pii`-tagged column is automatically covered by this policy. No additional configuration needed.

---

## End-to-End Recipe 2: Default-Deny for Unclassified Tables

### Scenario
New tables arrive in `main.landing` and should be inaccessible to all users until a data steward reviews and reclassifies them.

### Step 1: Create the Classification Governed Tag

```python
execute_sql("""
    CREATE GOVERNED TAG IF NOT EXISTS classification
      DESCRIPTION 'Review status for data governance'
      VALUES ('unverified', 'in-review', 'approved')
""")
```

### Step 2: Create the Block-All UDF

```python
execute_sql("""
    CREATE OR REPLACE FUNCTION main.security.block_all()
    RETURNS BOOLEAN
    RETURN FALSE
""")

# Grant EXECUTE to the governance team (policy creator) only — end users do not need it
w.grants.update(
    securable_type=SecurableType.FUNCTION,
    full_name="main.security.block_all",
    changes=[
        PermissionsChange(add=[Privilege.EXECUTE], principal="governance-team")
    ],
)
```

### Step 3: Create a Job/Pipeline to Tag New Tables as Unverified

```python
# Run this as part of a daily job or triggered via Event Log
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT table_catalog, table_schema, table_name
        FROM system.information_schema.tables
        WHERE table_catalog = 'main'
          AND table_schema = 'landing'
    """,
)

for row in result.result.data_array or []:
    catalog, schema, table = row
    # Check if already tagged
    tag_check = w.statement_execution.execute_statement(
        warehouse_id=WAREHOUSE_ID,
        statement=f"""
            SELECT COUNT(*)
            FROM system.information_schema.table_tags
            WHERE catalog_name = '{catalog}'
              AND schema_name = '{schema}'
              AND table_name = '{table}'
              AND tag_name = 'classification'
        """,
    )
    count = int(tag_check.result.data_array[0][0])
    if count == 0:
        execute_sql(
            f"ALTER TABLE {catalog}.{schema}.{table} "
            f"SET TAGS ('classification' = 'unverified')"
        )
        print(f"Tagged {catalog}.{schema}.{table} as unverified")
```

### Step 4: Create the Default-Deny ABAC Policy

```python
from databricks.sdk.service.catalog import (
    FunctionArgument, PolicyInfo, PolicyType, RowFilterOptions, SecurableType,
)

w.policies.create_policy(
    PolicyInfo(
        name="block_unverified_tables",
        comment="Block all access to tables pending data governance review",
        on_securable_type=SecurableType.CATALOG,
        on_securable_fullname="main",
        for_securable_type=SecurableType.TABLE,
        policy_type=PolicyType.POLICY_TYPE_ROW_FILTER,
        to_principals=["account users"],
        except_principals=["data-admins", "data-stewards"],
        when_condition="has_tag_value('classification', 'unverified')",
        row_filter=RowFilterOptions(
            function_name="main.security.block_all",
            using=[],
        ),
    )
)
```

### Step 5: Promote a Table After Review

```python
# After a data steward approves a table
execute_sql("""
    ALTER TABLE main.landing.new_customer_data
    UNSET TAGS ('classification')
""")

# Then apply the approved tag
execute_sql("""
    ALTER TABLE main.landing.new_customer_data
    SET TAGS ('classification' = 'approved')
""")
```

Once the `unverified` tag is removed, the block-all policy no longer matches the table and access is restored.

---

## Audit Queries

### Recent Policy Changes

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          event_time,
          user_identity.email AS changed_by,
          action_name,
          request_params
        FROM system.access.audit
        WHERE action_name IN (
          'createPolicy', 'deletePolicy', 'getPolicy', 'listPolicies'
        )
        ORDER BY event_time DESC
        LIMIT 100
    """,
)
```

### Recent Tag Assignment and Removal Events

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          event_time,
          user_identity.email AS changed_by,
          action_name,
          request_params
        FROM system.access.audit
        WHERE action_name IN (
          'createEntityTagAssignment',
          'deleteEntityTagAssignment'
        )
        ORDER BY event_time DESC
        LIMIT 100
    """,
)
```

### Who Accessed a Policy-Protected Table

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          event_time,
          user_identity.email,
          action_name,
          request_params.table_full_name AS table_name
        FROM system.access.audit
        WHERE action_name = 'commandSubmit'
          AND request_params.table_full_name LIKE 'main.hr.%'
        ORDER BY event_time DESC
        LIMIT 200
    """,
)
```

---

## Performance Testing Template

Test UDFs on at least 1 million rows before deploying to production:

```python
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        WITH test_data AS (
          SELECT
            CONCAT('***-**-', RIGHT(CAST(id AS STRING), 4)) AS masked_ssn,
            current_timestamp() AS ts
          FROM (
            SELECT LPAD(CAST(id AS STRING), 9, '0') AS id
            FROM range(1000000)
          )
        )
        SELECT
          COUNT(*) AS rows_processed,
          MAX(ts) AS end_time,
          MIN(ts) AS start_time
        FROM test_data
    """,
)
```

---

## Resources

- [ABAC common patterns](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/common-patterns)
- [ABAC performance considerations](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/performance)
- [ABAC best practices](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/best-practices)
- [ABAC policy evaluation](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/policy-evaluation)
- [system.access.audit](https://docs.databricks.com/aws/en/administration-guide/system-tables/audit.html)

## Related Files

- [abac-overview.md](abac-overview.md) — Key concepts and when to use ABAC
- [abac-governed-tags.md](abac-governed-tags.md) — Creating the tag taxonomy used in these patterns
- [abac-policies.md](abac-policies.md) — Full policy syntax and SDK reference
- [abac-data-classification.md](abac-data-classification.md) — Using AI classification results to identify which columns to tag
- [traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md) — Per-table approach and migration path
- [uc-acls.md](uc-acls.md) — GRANT EXECUTE on UDFs
