# Governed Tags

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Governed tags are the foundation of ABAC. They are account-level metadata labels with standardized keys and optional enumerated values. ABAC policies use `has_tag()` and `has_tag_value()` to evaluate these tags at query time and determine which tables and columns a policy applies to.

## Contents

- **Concepts** — user-governed vs. system governed tags, tag structure, inheritance rules, quotas, disallowed characters
- **SQL — Create / Alter / Drop / Show** — `CREATE GOVERNED TAG`, `ALTER GOVERNED TAG`, `DROP GOVERNED TAG`, `SHOW GOVERNED TAGS`
- **SQL — Applying Tags to Securable Objects** — tables, columns, schemas, catalogs; runtime 16.1+ shorthand syntax
- **Gotcha: Dropping a Tagged Column** — must `UNSET TAG` before `DROP COLUMN`
- **Required Permissions** — `APPLY TAG`, `ASSIGN`, `USE SCHEMA`, `USE CATALOG` per action
- **Python SDK** — create tags, list tags, apply to tables/columns, bulk tag from a list, query system tables
- **Recommended Tag Taxonomy** — starter set: `sensitivity`, `pii`, `domain`, `classification`

---

## Concepts

### Tag Types

| Type | Created By | Icon | Mutable |
|------|-----------|------|---------|
| User-Governed Tags | Account admins or users with `CREATE` permission | Lock | Yes |
| System Governed Tags | Databricks (for Data Classification) | Wrench | No — read-only |

### Tag Structure
- **Key-only**: tag presence signals a condition (e.g., `isPii`)
- **Key-value**: tag value carries semantic meaning (e.g., `pii = 'ssn'`, `sensitivity = 'high'`)

### Tag Inheritance
- Tags applied to a **catalog** or **schema** cascade down to contained tables
- Column tags do **not** inherit — they must be applied directly to each column
- Inheritance can be overridden at lower levels

### Constraints

| Constraint | Limit |
|-----------|-------|
| Governed tags per account | 1,000 |
| Allowed values per tag | 50 |
| Tag key/value max length | 256 characters |
| Tags per securable object | 50 |
| Column tags per table | 1,000 |

**Disallowed characters in keys/values:** `* . / < > % & ? \ =` and ASCII control characters 0–31. No leading or trailing whitespace. Keys and values are case-sensitive.

---

## SQL — Create / Alter / Drop / Show

### Create Governed Tags

```sql
-- Key-only tag (presence signals a condition)
CREATE GOVERNED TAG isPii;

-- Tag with enumerated allowed values
CREATE GOVERNED TAG sensitivity_level VALUES ('low', 'medium', 'high');

-- Tag with description and allowed values
CREATE GOVERNED TAG pii
  DESCRIPTION 'Indicates what kind of PII the asset contains'
  VALUES ('ssn', 'ccn', 'dob', 'email', 'phone', 'name', 'address');
```

### Alter Governed Tags

`SET VALUES` is declarative — it replaces the entire allowed values list:

```sql
-- Add a new allowed value
ALTER GOVERNED TAG sensitivity_level SET VALUES ('low', 'medium', 'high', 'critical');

-- Update description only
ALTER GOVERNED TAG pii SET DESCRIPTION 'PII data type indicator for ABAC policies';

-- Remove value constraints (make key-only)
ALTER GOVERNED TAG isPii SET VALUES ();
```

### Drop Governed Tags

Dropping a governed tag does not remove it from objects where it was applied — those assignments become ungoverned. Any ABAC policy referencing the dropped tag will cause queries to fail. Drop with care.

```sql
DROP GOVERNED TAG isPii;
```

### Show Governed Tags

```sql
-- List all governed tags in the account
SHOW GOVERNED TAGS;

-- Filter with a pattern
SHOW GOVERNED TAGS LIKE 'pii*';
SHOW GOVERNED TAGS LIKE 'class.*';
```

`SHOW GOVERNED TAGS` returns: Tag Key, Description, Values, Create Time, Update Time.

---

## SQL — Applying Tags to Securable Objects

### Tables

```sql
-- Apply tag to a table
ALTER TABLE <catalog>.<schema>.<table> SET TAGS ('<key>' = '<value>');

-- Apply multiple tags at once
ALTER TABLE <catalog>.<schema>.<table>
SET TAGS ('sensitivity' = 'high', 'domain' = 'finance');

-- Remove a tag from a table
ALTER TABLE <catalog>.<schema>.<table> UNSET TAGS ('<key>');
```

### Columns

```sql
-- Apply tag to a column
ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN <column> SET TAGS ('<key>' = '<value>');

-- Apply multiple column tags
ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN ssn SET TAGS ('pii' = 'ssn');

ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN email SET TAGS ('pii' = 'email');

-- Remove a column tag
ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN <column> UNSET TAGS ('<key>');
```

### Schemas

```sql
-- Tags on a schema cascade to all tables in the schema
ALTER SCHEMA <catalog>.<schema> SET TAGS ('region' = 'eu');
ALTER SCHEMA <catalog>.<schema> UNSET TAGS ('region');
```

### Catalogs

```sql
ALTER CATALOG <catalog> SET TAGS ('env' = 'production');
ALTER CATALOG <catalog> UNSET TAGS ('env');
```

### Runtime 16.1+ Shorthand Syntax

```sql
SET TAG ON CATALOG <catalog> `<key>` = `<value>`;
UNSET TAG ON CATALOG <catalog> <key>;

SET TAG ON SCHEMA <catalog>.<schema> `<key>` = `<value>`;
UNSET TAG ON TABLE <catalog>.<schema>.<table> <key>;
```

---

## Gotcha: Dropping a Tagged Column

You must remove the governed tag **before** dropping the column. Attempting to drop a column that has an active governed tag will fail:

```sql
-- Step 1: Remove the governed tag
ALTER TABLE <catalog>.<schema>.<table>
ALTER COLUMN ssn UNSET TAGS ('pii');

-- Step 2: Now drop the column
ALTER TABLE <catalog>.<schema>.<table> DROP COLUMN ssn;
```

---

## Required Permissions

| Action | Permissions Required |
|--------|---------------------|
| Create governed tag | Account admin or `CREATE GOVERNED TAG` |
| Apply tag to a table/schema/catalog | `APPLY TAG` on the object + `USE SCHEMA` + `USE CATALOG` + `ASSIGN` on the governed tag |
| Apply tag to a column | Same as table-level, applied to the parent table |
| View tags on an object | `SELECT` or `DESCRIBE` on the object |
| Drop governed tag | Account admin or owner of the tag |

---

## Python SDK

### Create Governed Tags

Governed tag creation is managed via SQL execution:

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

def execute_sql(warehouse_id: str, statement: str) -> None:
    w.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=statement,
    )

WAREHOUSE_ID = "<warehouse-id>"

# Create a key-value governed tag
execute_sql(WAREHOUSE_ID, """
    CREATE GOVERNED TAG IF NOT EXISTS pii
      DESCRIPTION 'PII data type indicator for ABAC policies'
      VALUES ('ssn', 'ccn', 'dob', 'email', 'phone', 'name')
""")

# Create a sensitivity classification tag
execute_sql(WAREHOUSE_ID, """
    CREATE GOVERNED TAG IF NOT EXISTS sensitivity
      DESCRIPTION 'Data sensitivity level'
      VALUES ('public', 'internal', 'confidential', 'restricted')
""")
```

### List Governed Tags

```python
import json

result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="SHOW GOVERNED TAGS",
)

for row in result.result.data_array or []:
    print(f"Key: {row[0]}, Values: {row[2]}, Description: {row[1]}")
```

### Apply Tags to Tables and Columns

```python
# Tag a table
execute_sql(WAREHOUSE_ID, """
    ALTER TABLE main.hr.employees
    SET TAGS ('sensitivity' = 'confidential', 'domain' = 'hr')
""")

# Tag a specific column
execute_sql(WAREHOUSE_ID, """
    ALTER TABLE main.hr.employees
    ALTER COLUMN ssn SET TAGS ('pii' = 'ssn')
""")

execute_sql(WAREHOUSE_ID, """
    ALTER TABLE main.hr.employees
    ALTER COLUMN email SET TAGS ('pii' = 'email')
""")
```

### Bulk Tag Columns from a List

```python
from typing import List, Tuple

def apply_column_tags(
    warehouse_id: str,
    table_full_name: str,
    column_tags: List[Tuple[str, str, str]],  # (column, tag_key, tag_value)
) -> None:
    for column, tag_key, tag_value in column_tags:
        w.statement_execution.execute_statement(
            warehouse_id=warehouse_id,
            statement=f"""
                ALTER TABLE {table_full_name}
                ALTER COLUMN {column}
                SET TAGS ('{tag_key}' = '{tag_value}')
            """,
        )

apply_column_tags(
    WAREHOUSE_ID,
    "main.hr.employees",
    [
        ("ssn", "pii", "ssn"),
        ("email", "pii", "email"),
        ("date_of_birth", "pii", "dob"),
        ("phone", "pii", "phone"),
    ],
)
```

### Query Tags on Objects via System Tables

```python
# List all tagged columns in a catalog
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT
          catalog_name,
          schema_name,
          table_name,
          column_name,
          tag_name,
          tag_value
        FROM system.information_schema.column_tags
        WHERE catalog_name = 'main'
        ORDER BY schema_name, table_name, column_name
    """,
)

# List all tagged tables in a catalog
result = w.statement_execution.execute_statement(
    warehouse_id=WAREHOUSE_ID,
    statement="""
        SELECT catalog_name, schema_name, table_name, tag_name, tag_value
        FROM system.information_schema.table_tags
        WHERE catalog_name = 'main'
        ORDER BY schema_name, table_name
    """,
)
```

---

## Recommended Tag Taxonomy

Start with a small, well-defined set before writing policies. Add values incrementally:

```sql
-- Sensitivity classification (drives row-level and object-level policies)
CREATE GOVERNED TAG sensitivity
  DESCRIPTION 'Data sensitivity level'
  VALUES ('public', 'internal', 'confidential', 'restricted');

-- PII type (drives column mask policies)
CREATE GOVERNED TAG pii
  DESCRIPTION 'Type of personally identifiable information'
  VALUES ('ssn', 'ccn', 'dob', 'email', 'phone', 'name', 'address', 'passport', 'license');

-- Domain ownership (for routing and stewardship, not direct ABAC)
CREATE GOVERNED TAG domain
  DESCRIPTION 'Business domain that owns this data asset'
  VALUES ('hr', 'finance', 'marketing', 'engineering', 'legal');

-- Classification status (for default-deny unverified tables pattern)
CREATE GOVERNED TAG classification
  DESCRIPTION 'Review status of the table for data governance'
  VALUES ('unverified', 'in-review', 'approved');
```

---

## Resources

- [Governed tags overview](https://docs.databricks.com/aws/en/admin/governed-tags/)
- [Apply tags to Unity Catalog objects](https://docs.databricks.com/aws/en/data-governance/unity-catalog/tags)
- [SQL reference: CREATE GOVERNED TAG](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-create-governed-tag.html)
- [SQL reference: ALTER GOVERNED TAG](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-alter-governed-tag.html)
- [SQL reference: DROP GOVERNED TAG](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-drop-governed-tag.html)
- [SQL reference: SHOW GOVERNED TAGS](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-aux-show-governed-tags.html)

## Related Files

- [abac-overview.md](abac-overview.md) — ABAC concepts and how tags connect to policies
- [abac-policies.md](abac-policies.md) — Using `has_tag()` / `has_tag_value()` inside policy `WHEN` and `MATCH COLUMNS` clauses
- [abac-data-classification.md](abac-data-classification.md) — System-generated `class.*` tags from AI classification
- [uc-acls.md](uc-acls.md) — ASSIGN permission required to apply governed tags
