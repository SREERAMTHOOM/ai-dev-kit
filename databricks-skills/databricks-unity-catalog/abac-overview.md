# Unity Catalog ABAC Overview

**For AI Agents:** This skill is reference-only. Recommend the SQL, SDK code, or CLI commands required — do not execute any code unless the user explicitly asks you to run it.

Attribute-Based Access Control (ABAC) is Unity Catalog's policy-driven model for row-level and column-level data security. It went **Generally Available in April 2026**. Unlike per-table row filters and column masks, ABAC policies attach at the catalog, schema, or table level and apply automatically to all tables that carry matching governed tags — a single policy can protect thousands of tables, including ones that don't exist yet.

## Contents

- **The Three-Feature Model** — governed tags, ABAC policies, data classification and how they connect
- **Key Concepts** — policy attachment points, `has_tag()` / `has_tag_value()`, policy clauses (`TO`, `EXCEPT`, `WHEN`, `MATCH COLUMNS`), identity functions
- **ABAC vs. Traditional Row Filters / Column Masks** — scope, targeting, bypass, auto-coverage, separation of duties
- **ABAC vs. Dynamic Views** — same object name, audit trail, governance metadata, performance
- **When to Use ABAC / Traditional Filters / Combining Both** — decision guide and conflict rules
- **Compute Requirements** — supported runtimes (DBR 16.4+, serverless), fail-closed behavior for older runtimes
- **Operations That Require EXCEPT Exemption** — time travel, cloning, Delta Sharing, vector search, pipelines
- **Policy Quotas** — limits per metastore, catalog/schema, table, principals, MATCH COLUMNS
- **Separation of Duties Model** — who needs what permission to create tags, policies, and query data
- **Dependency Safeguards** — fail-closed behavior when tags or UDFs are deleted

---

## The Three-Feature Model

ABAC in Unity Catalog is composed of three tightly coupled features:

| Feature | Status | Purpose |
|---------|--------|---------|
| **Governed Tags** | GA | Standardized account-level metadata labels — the foundation ABAC policies evaluate against |
| **ABAC Policies** | GA | Dynamic row/column security rules that activate based on tag conditions |
| **Data Classification** | Public Preview | AI-powered detection and tagging of sensitive columns — feeds tag recommendations into ABAC |

All three work together: Classification identifies sensitive data → Governed Tags label it → ABAC Policies enforce access based on those labels.

---

## Key Concepts

### Policy Attachment Points

A policy can be attached to a **catalog**, **schema**, or **table**. Policies attached at a higher level automatically cover all qualifying tables within that scope.

```
Catalog  ← attach here to cover all schemas/tables in the catalog
└── Schema  ← attach here to cover all tables in the schema
    └── Table  ← attach here for table-specific policy
```

### Tag Condition Functions

These built-in SQL functions are used inside `WHEN` and `MATCH COLUMNS` clauses to identify which tables and columns a policy applies to:

| Function | Returns | Example |
|----------|---------|---------|
| `has_tag('key')` | `TRUE` if object has the tag key (any value) | `has_tag('pii')` |
| `has_tag_value('key', 'value')` | `TRUE` if object has the tag with exact value | `has_tag_value('sensitivity', 'high')` |

### Policy Clauses

| Clause | Purpose |
|--------|---------|
| `ON` | The securable object the policy attaches to (catalog, schema, or table) |
| `TO` | Principals the policy applies to |
| `EXCEPT` | Principals exempt from the policy (e.g., admins, pipelines, Delta Share owners) |
| `WHEN` | Table-level boolean condition — does the policy apply to this table at all? |
| `MATCH COLUMNS` | Identifies target columns by tag condition; assigns an alias for use as a UDF argument |
| `ON COLUMN` | (Column masks only) Which matched column alias to mask |
| `USING COLUMNS` | Maps UDF arguments — can be matched column aliases or string constants |

### Identity Functions

Used inside UDFs to make policies dynamic based on who is running the query:

| Function | Returns |
|----------|---------|
| `current_user()` | Email address of the caller |
| `is_account_group_member('group')` | `TRUE` if caller belongs to the account-level group |
| `session_user()` | Email address of the session user |

---

## ABAC vs. Traditional Row Filters / Column Masks

| Factor | Traditional (`ALTER TABLE`) | ABAC Policies |
|--------|----------------------------|---------------|
| Scope | One table at a time | Catalog, schema, or table — covers many tables dynamically |
| Column/table targeting | Statically named at attachment time | Tag-based (`has_tag()`) — resolved dynamically at query time |
| Who can bypass | Table owners can modify or remove their own filters | Only catalog/schema owners; table owners cannot bypass |
| New tables auto-covered | No — must configure each new table | Yes — when they carry matching governed tags |
| Principal exemptions | Must embed in UDF logic | Clean `EXCEPT` clause |
| SQL management | `ALTER TABLE SET ROW FILTER` | `CREATE POLICY`, `SHOW POLICIES` |
| Policy visibility | `INFORMATION_SCHEMA.ROW_FILTERS` | `SHOW EFFECTIVE POLICIES` |
| Separation of duties | Low — table owners control their own policies | High — governance team sets policy; data producers tag objects |

---

## ABAC vs. Dynamic Views

| Factor | ABAC / Row Filters | Dynamic Views |
|--------|--------------------|---------------|
| Users query same object name | Yes — same table | No — must query the view, not the table |
| Spans multiple source tables | No | Yes |
| Audit trail | Full audit in system tables | Limited |
| Governance metadata | Visible via `SHOW EFFECTIVE POLICIES` | Embedded in view definition, not queryable |
| Performance | Often better — policies can enable predicate pushdown | Better for complex multi-table reshaping |
| Protection against probing | Strong — UC enforces at catalog layer | Weaker without governance metadata |

---

## When to Use ABAC

- Your data estate is large and growing — new tables should be protected automatically
- Your organization separates governance duties from data production
- You want `EXCEPT` clauses to cleanly exempt specific groups (e.g., pipelines, Delta Sharing owners) without embedding logic in UDFs
- You are hitting scale limits with per-table filter/mask configuration
- You need consistent, auditable policy coverage across schemas or catalogs

## When to Use Traditional Filters

- Each table has strict, unique logic that doesn't generalize across tables
- Table owners should own and manage their own protection logic
- Your estate is small and stable — a handful of tables that change infrequently
- You are on Databricks Runtime < 16.4 and cannot upgrade yet

## Combining Both

Both approaches can coexist on the same table. Conflict rules at query time:
- Only **one distinct row filter** can apply per user per table
- Only **one distinct column mask** can apply per user per column
- If different functions would resolve to the same user/column — even if functionally identical — Databricks **blocks access** rather than guessing

---

## Compute Requirements

| Compute Type | Requirement |
|--------------|-------------|
| Serverless | Supported (recommended) |
| Standard (shared) | Databricks Runtime 16.4+ |
| Dedicated | Databricks Runtime 16.4+ with fine-grained access control filtering enabled |
| Runtimes < 16.4 | **Cannot access ABAC-protected tables** — fail-closed |

**Workaround for legacy runtimes:** Scope policies to groups and use `EXCEPT` to exclude workloads running on older runtimes until they are upgraded.

---

## Operations That Require EXCEPT Exemption

These operations cannot work through ABAC policies and require the running identity to be in the `EXCEPT` clause:

- Time travel queries (`VERSION AS OF`, `TIMESTAMP AS OF`)
- Deep and shallow cloning (`CLONE`)
- Delta Sharing transfers (share owner must be in `EXCEPT`)
- Vector search index creation and syncing
- Pipeline refreshes that require full data access

---

## Policy Quotas

| Resource | Limit |
|----------|-------|
| Policies per metastore | 10,000 |
| Policies per catalog or schema | 100 |
| Policies per table | 50 |
| Principals per policy (`TO` + `EXCEPT` combined) | 20 |
| `MATCH COLUMNS` expressions per policy | 3 |

---

## Separation of Duties Model

ABAC is designed to separate who governs data from who produces and queries it:

| Role | Permission Required |
|------|-------------------|
| Create governed tag taxonomy | Account admin or `CREATE` on governed tags |
| Apply tags to objects | `ASSIGN` on governed tag + `APPLY TAG` on object |
| Create/manage ABAC policies | `MANAGE` on securable + `EXECUTE` on UDF |
| Create data objects | `CREATE TABLE` or equivalent |
| Query data | `SELECT` on table |

This means a data engineer creating tables cannot override or remove a policy set by the governance team — a stronger enforcement model than table-level filters.

---

## Dependency Safeguards (Fail-Closed)

ABAC is designed to fail safely when dependencies are broken:

| Action | Result |
|--------|--------|
| Delete a governed tag referenced in a policy | Queries fail with `INVALID_PARAMETER_VALUE.UC_ABAC_UNKNOWN_TAG_POLICY` |
| Drop a UDF referenced in a policy | Queries fail with `UC_DEPENDENCY_DOES_NOT_EXIST` |
| Drop a column with an active governed tag | Blocked at DDL — must `UNSET TAG` first |

---

## Resources

- [Unity Catalog ABAC overview](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/)
- [ABAC core concepts](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/core-concepts)
- [ABAC requirements and compute support](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/requirements)
- [ABAC vs. row-level security and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/abac-vs-rls-cm)
- [ABAC best practices](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/best-practices)
- [Blog: ABAC, row filtering, column masking, governed tags, and data classification are now GA](https://www.databricks.com/blog/abac-row-filtering-and-column-masking-policies-governed-tags-and-data-classification-are-now)

## Recommended Reading Order

For a complete ABAC implementation, read the files in this order:

1. **[uc-acls.md](uc-acls.md)** — Set up object privileges first (prerequisite)
2. **[abac-governed-tags.md](abac-governed-tags.md)** — Create and apply governed tags
3. **[traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md)** — Understand the traditional approach and migration path
4. **[abac-policies.md](abac-policies.md)** — Create row filter and column mask policies
5. **[abac-data-classification.md](abac-data-classification.md)** — Use AI classification to drive tag recommendations
6. **[abac-patterns.md](abac-patterns.md)** — Reusable UDF recipes and end-to-end walkthroughs
