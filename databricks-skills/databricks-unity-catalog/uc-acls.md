# Unity Catalog ACLs — Privileges & Access Management

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Prerequisite reference for all ABAC and FGAC work. Object privileges control **who can reach** a securable object. Row filters, column masks, and ABAC policies control **what they see** once they have access. Both layers must be configured correctly.

## Contents

- **Privilege Hierarchy** — cascading permissions from Catalog → Schema → Table
- **Key Privileges Reference** — privilege types, what each allows, and EXECUTE distinction for creators vs. end users
- **SQL — GRANT / REVOKE** — minimum grants to query a table, schema-wide, write, volume, function EXECUTE, governed tag ASSIGN, revoke, inspect
- **Ownership** — transfer object ownership with ALTER ... OWNER TO
- **Python SDK — Grants Management** — grant, revoke, get effective grants, get direct grants
- **Query Grants via System Tables** — SQL for auditing who has access to what
- **Best Practices** — groups over users, least privilege, schema-level grants, audit cadence

---

## Privilege Hierarchy

Privileges cascade from parent to child objects. Granting at a higher level implicitly allows access to contained objects unless explicitly overridden.

```
Metastore
└── Catalog          → USE CATALOG
    └── Schema       → USE SCHEMA
        ├── Table    → SELECT, MODIFY, ALL PRIVILEGES
        ├── View     → SELECT
        ├── Volume   → READ VOLUME, WRITE VOLUME
        ├── Function → EXECUTE   ← required by the creator (policy, row filter, or column mask); end users do not need it
        └── Model    → EXECUTE
```

---

## Key Privileges Reference

| Object | Privilege | What It Allows |
|--------|-----------|----------------|
| Catalog | `USE CATALOG` | Access schemas within the catalog |
| Schema | `USE SCHEMA` | Access objects within the schema |
| Table | `SELECT` | Read rows from the table |
| Table | `MODIFY` | INSERT, UPDATE, DELETE |
| Table | `ALL PRIVILEGES` | Full table access |
| Volume | `READ VOLUME` | Read files from volume path |
| Volume | `WRITE VOLUME` | Write files to volume path |
| Function | `EXECUTE` | Required by the **creator** — the identity running `CREATE POLICY`, `ALTER TABLE SET ROW FILTER`, or `ALTER TABLE ALTER COLUMN SET MASK`. End users querying protected tables do not need it. |
| Governed Tag | `ASSIGN` | Apply governed tag to securable objects |
| External Location | `CREATE EXTERNAL TABLE` | Create tables on that storage path |
| External Location | `READ FILES` | Read files from that storage location |

---

## SQL — GRANT / REVOKE

### Minimum Grants to Query a Table

Every user or group needs all three levels before they can run `SELECT` on a table:

```sql
GRANT USE CATALOG ON CATALOG <catalog> TO `<group-or-user>`;
GRANT USE SCHEMA ON SCHEMA <catalog>.<schema> TO `<group-or-user>`;
GRANT SELECT ON TABLE <catalog>.<schema>.<table> TO `<group-or-user>`;
```

### Schema-Wide Read Access

Grant once at the schema level instead of per table:

```sql
GRANT USE CATALOG ON CATALOG <catalog> TO `<group>`;
GRANT USE SCHEMA ON SCHEMA <catalog>.<schema> TO `<group>`;
GRANT SELECT ON SCHEMA <catalog>.<schema> TO `<group>`;
```

### Write Access

```sql
GRANT MODIFY ON TABLE <catalog>.<schema>.<table> TO `<group>`;
```

### Volume Access

```sql
GRANT READ VOLUME ON VOLUME <catalog>.<schema>.<volume> TO `<group>`;
GRANT WRITE VOLUME ON VOLUME <catalog>.<schema>.<volume> TO `<group>`;
```

### Function EXECUTE

The `EXECUTE` requirement differs between ABAC and traditional row filters:

The rule is the same for ABAC policies, traditional row filters, and column masks: the **creator** needs `EXECUTE` on the UDF. End users querying the protected table do **not** need it.

| Approach | Who needs EXECUTE |
|----------|------------------|
| ABAC `CREATE POLICY` | The identity running `CREATE POLICY` |
| Traditional `ALTER TABLE SET ROW FILTER` | The identity running the `ALTER TABLE` statement |
| Traditional `ALTER TABLE ALTER COLUMN SET MASK` | The identity running the `ALTER TABLE` statement |

```sql
GRANT EXECUTE ON FUNCTION <catalog>.<schema>.<function> TO `<governance-team>`;
```

### Governed Tag ASSIGN

Required to apply governed tags to securable objects:

```sql
GRANT ASSIGN ON GOVERNED TAG <tag_key> TO `<group>`;
```

### Revoke Privileges

```sql
REVOKE SELECT ON TABLE <catalog>.<schema>.<table> FROM `<group>`;
REVOKE USE SCHEMA ON SCHEMA <catalog>.<schema> FROM `<group>`;
REVOKE EXECUTE ON FUNCTION <catalog>.<schema>.<function> FROM `<group>`;
```

### Inspect Existing Grants

```sql
-- All grants on a specific object
SHOW GRANTS ON TABLE <catalog>.<schema>.<table>;
SHOW GRANTS ON SCHEMA <catalog>.<schema>;
SHOW GRANTS ON CATALOG <catalog>;
SHOW GRANTS ON FUNCTION <catalog>.<schema>.<function>;

-- All grants held by a principal
SHOW GRANTS `<group-or-user>`;
```

---

## Ownership

The object owner has full privileges and can grant to others. Object owners cannot be locked out by ABAC policies attached to their own objects.

```sql
-- Transfer table ownership
ALTER TABLE <catalog>.<schema>.<table> OWNER TO `<group-or-user>`;

-- Transfer schema ownership
ALTER SCHEMA <catalog>.<schema> OWNER TO `<group>`;

-- Transfer catalog ownership
ALTER CATALOG <catalog> OWNER TO `<group>`;
```

---

## Python SDK — Grants Management

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import (
    PermissionsChange,
    Privilege,
    SecurableType,
)

w = WorkspaceClient()
```

### Grant Privileges

```python
# Grant SELECT on a table
w.grants.update(
    securable_type=SecurableType.TABLE,
    full_name="main.sales.transactions",
    changes=[
        PermissionsChange(add=[Privilege.SELECT], principal="analysts")
    ],
)
```

### Grant Multiple Privileges at Once

```python
# Minimum grants for a group to query a table
for securable_type, full_name, privilege in [
    (SecurableType.CATALOG, "main", Privilege.USE_CATALOG),
    (SecurableType.SCHEMA, "main.sales", Privilege.USE_SCHEMA),
    (SecurableType.TABLE, "main.sales.transactions", Privilege.SELECT),
]:
    w.grants.update(
        securable_type=securable_type,
        full_name=full_name,
        changes=[PermissionsChange(add=[privilege], principal="analysts")],
    )
```

### Grant EXECUTE on ABAC UDF

```python
w.grants.update(
    securable_type=SecurableType.FUNCTION,
    full_name="main.security.region_filter",
    changes=[
        PermissionsChange(add=[Privilege.EXECUTE], principal="analysts")
    ],
)
```

### Revoke Privileges

```python
w.grants.update(
    securable_type=SecurableType.TABLE,
    full_name="main.sales.transactions",
    changes=[
        PermissionsChange(remove=[Privilege.SELECT], principal="analysts")
    ],
)
```

### Get Effective Grants (Includes Inherited)

```python
grants = w.grants.get_effective(
    securable_type=SecurableType.TABLE,
    full_name="main.sales.transactions",
)
for assignment in grants.privilege_assignments or []:
    privileges = [p.value for p in assignment.privileges]
    print(f"{assignment.principal}: {privileges}")
```

### Get Direct Grants Only

```python
grants = w.grants.get(
    securable_type=SecurableType.TABLE,
    full_name="main.sales.transactions",
)
for assignment in grants.privilege_assignments or []:
    privileges = [p.value for p in assignment.privileges]
    print(f"{assignment.principal}: {privileges}")
```

---

## Query Grants via System Tables

```python
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

# All privileges in a catalog
result = w.statement_execution.execute_statement(
    warehouse_id="<warehouse-id>",
    statement="""
        SELECT grantor, grantee, object_type, object_name, privilege_type, is_grantable
        FROM system.information_schema.object_privileges
        WHERE object_catalog = '<catalog>'
        ORDER BY object_name, grantee
    """,
)

# Who has SELECT on a specific table
result = w.statement_execution.execute_statement(
    warehouse_id="<warehouse-id>",
    statement="""
        SELECT grantee, privilege_type
        FROM system.information_schema.object_privileges
        WHERE object_catalog = '<catalog>'
          AND object_schema = '<schema>'
          AND object_name = '<table>'
          AND privilege_type = 'SELECT'
    """,
)

# All privileges held by a group
result = w.statement_execution.execute_statement(
    warehouse_id="<warehouse-id>",
    statement="""
        SELECT object_type, object_name, privilege_type
        FROM system.information_schema.object_privileges
        WHERE grantee = '<group>'
        ORDER BY object_type, object_name
    """,
)
```

---

## Best Practices

1. **Grant to groups, not users** — group membership is centrally managed; user-level grants become unmaintainable at scale
2. **Least privilege** — grant only `SELECT` unless write access is explicitly required
3. **Schema-level grants for teams** — granting at schema level is simpler than per-table grants when a team needs access to all tables in a schema
4. **Audit regularly** — query `system.information_schema.object_privileges` to review who has access to sensitive schemas
5. **ACLs and ABAC are complementary** — ACLs control who reaches the object; row filters and column masks control what they see

---

## Resources

- [Manage privileges in Unity Catalog](https://docs.databricks.com/aws/en/data-governance/unity-catalog/manage-privileges/index.html)
- [Unity Catalog privileges and securable objects](https://docs.databricks.com/aws/en/data-governance/unity-catalog/manage-privileges/privileges.html)
- [system.information_schema.object_privileges](https://docs.databricks.com/aws/en/sql/language-manual/information-schema/object_privileges.html)
- [Databricks SDK for Python — Grants](https://databricks-sdk-py.readthedocs.io/en/latest/workspace/catalog/grants.html)

## Related Files

- [abac-overview.md](abac-overview.md) — ABAC concepts and how policies build on top of ACLs
- [abac-policies.md](abac-policies.md) — Creating row filter and column mask policies
- [abac-governed-tags.md](abac-governed-tags.md) — Tag ASSIGN permission and governed tag management
