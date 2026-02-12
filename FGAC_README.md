# FGAC — Fine-Grained Access Control for Databricks Unity Catalog

Fine-Grained Access Control (FGAC) policies bind governed tags to masking UDFs or row filters, scoped to catalogs, schemas, or tables, and targeted at specific principals. This document covers the complete FGAC feature set: governed tags, tag assignments, masking UDFs, policy management, the Python SDK, MCP tools, and the human-in-the-loop governance workflow.

**Databricks Docs:**
- [FGAC Overview](https://docs.databricks.com/data-governance/unity-catalog/abac/)
- [FGAC Policies](https://docs.databricks.com/data-governance/unity-catalog/abac/policies)
- [FGAC Tutorial](https://docs.databricks.com/data-governance/unity-catalog/abac/tutorial)
- [UDF Best Practices](https://docs.databricks.com/data-governance/unity-catalog/abac/udf-best-practices)
- [Governed Tags](https://docs.databricks.com/admin/governed-tags/)

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Step 1: Governed Tags](#step-1-governed-tags)
- [Step 2: Tag Assignments](#step-2-tag-assignments)
- [Step 3: Masking UDFs](#step-3-masking-udfs)
- [Step 4: FGAC Policies](#step-4-fgac-policies)
- [Policy Quotas](#policy-quotas)
- [SQL That Does NOT Exist](#sql-that-does-not-exist)
- [Discovery Queries](#discovery-queries)
- [Python SDK Reference](#python-sdk-reference)
- [MCP Tools Reference](#mcp-tools-reference)
- [Human-in-the-Loop Governance Workflow](#human-in-the-loop-governance-workflow)
- [Approval Token Internals](#approval-token-internals)
- [Environment Variables](#environment-variables)
- [Threat Model](#threat-model)
- [Common Errors](#common-errors)
- [Best Practices](#best-practices)
- [Source Files](#source-files)

---

## Architecture Overview

FGAC policies follow a 4-step setup:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Governed Tags│───>│    Tag       │───>│  Masking     │───>│    FGAC      │
│ (UI only)    │    │ Assignments  │    │    UDFs      │    │  Policies    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
      Step 1             Step 2              Step 3              Step 4
```

1. **Governed Tags** — Define a classification taxonomy (e.g., `pii_type` with values `ssn`, `email`, `phone`)
2. **Tag Assignments** — Apply tags to columns or tables via SQL
3. **Masking UDFs** — Create deterministic functions that transform sensitive values
4. **FGAC Policies** — Bind tags to UDFs with principal scoping (who sees masked data, who is exempt)

---

## Step 1: Governed Tags

Governed tags **cannot** be created via SQL or API. They must be created in the Databricks UI.

### Creating a Governed Tag (UI Steps)

1. Navigate to **Catalog** in the workspace
2. Select **Governed Tags** from the left panel
3. Click **Create governed tag**
4. Configure:
   - **Tag Key**: e.g., `pii_type`
   - **Allowed Values**: e.g., `ssn`, `email`, `phone`, `credit_card`, `address`
   - **Description**: e.g., "PII classification for FGAC policies"

> **Note:** Tag data is stored as plain text and may be replicated globally. Avoid putting sensitive information in tag names or values.

> **Propagation delay:** Newly created governed tags need ~30 seconds to propagate before they can be used in tag assignments.

---

## Step 2: Tag Assignments

### Modern Syntax (DBR 16.1+)

```sql
-- Set tag on column
SET TAG ON COLUMN catalog.schema.table.column_name 'pii_type' = 'ssn';

-- Set tag on table
SET TAG ON TABLE catalog.schema.table 'data_classification' = 'confidential';

-- Set tag on schema
SET TAG ON SCHEMA catalog.schema 'environment' = 'production';

-- Set tag on catalog
SET TAG ON CATALOG my_catalog 'department' = 'finance';

-- Remove tag
UNSET TAG ON COLUMN catalog.schema.table.column_name 'pii_type';
UNSET TAG ON TABLE catalog.schema.table 'data_classification';
```

### Legacy Syntax (all versions)

```sql
-- Set tag on column
ALTER TABLE catalog.schema.table
ALTER COLUMN column_name SET TAGS ('pii_type' = 'ssn');

-- Set tag on table
ALTER TABLE catalog.schema.table
SET TAGS ('data_classification' = 'confidential');

-- Remove tag
ALTER TABLE catalog.schema.table
ALTER COLUMN column_name UNSET TAGS ('pii_type');
```

### Querying Existing Tags

```sql
-- Column tags
SELECT tag_name, tag_value, column_name
FROM system.information_schema.column_tags
WHERE catalog_name = 'my_catalog'
  AND schema_name = 'my_schema'
  AND table_name = 'my_table';

-- Table tags
SELECT tag_name, tag_value
FROM system.information_schema.table_tags
WHERE catalog_name = 'my_catalog'
  AND schema_name = 'my_schema'
  AND table_name = 'my_table';

-- All tag assignments in a catalog
SELECT 'COLUMN' AS securable_type,
       CONCAT(catalog_name, '.', schema_name, '.', table_name, '.', column_name) AS securable_name,
       tag_name, tag_value
FROM system.information_schema.column_tags
WHERE catalog_name = 'my_catalog';
```

---

## Step 3: Masking UDFs

Masking UDFs must be `DETERMINISTIC` and use simple `CASE` statements. No external calls or nested UDFs.

> **Cross-catalog UDFs:** Masking UDFs do not need to be in the same catalog/schema as the policy scope. A common pattern is a shared governance schema (e.g., `governance.masking_udfs`) containing all masking functions, referenced by policies across multiple catalogs.

### Column Mask UDFs

```sql
-- Full mask: replaces all characters with *
CREATE OR REPLACE FUNCTION catalog.schema.mask_full(value STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN value IS NULL THEN NULL
    ELSE REPEAT('*', LENGTH(value))
END;

-- Partial mask: show last 4 characters
CREATE OR REPLACE FUNCTION catalog.schema.mask_partial(value STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN value IS NULL THEN NULL
    WHEN LENGTH(value) <= 4 THEN REPEAT('*', LENGTH(value))
    ELSE CONCAT(REPEAT('*', LENGTH(value) - 4), RIGHT(value, 4))
END;

-- SSN: ***-**-XXXX
CREATE OR REPLACE FUNCTION catalog.schema.mask_ssn(ssn STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN ssn IS NULL THEN NULL
    WHEN LENGTH(REGEXP_REPLACE(ssn, '[^0-9]', '')) >= 4
        THEN CONCAT('***-**-', RIGHT(REGEXP_REPLACE(ssn, '[^0-9]', ''), 4))
    ELSE '***-**-****'
END;

-- Email: j***@example.com
CREATE OR REPLACE FUNCTION catalog.schema.mask_email(email STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN email IS NULL THEN NULL
    WHEN INSTR(email, '@') > 1
        THEN CONCAT(LEFT(email, 1), '***@', SUBSTRING(email, INSTR(email, '@') + 1))
    ELSE '***@***.***'
END;

-- Credit card: ****-****-****-1234
CREATE OR REPLACE FUNCTION catalog.schema.mask_credit_card(card_number STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN card_number IS NULL THEN NULL
    WHEN LENGTH(REGEXP_REPLACE(card_number, '[^0-9]', '')) >= 4
        THEN CONCAT('****-****-****-', RIGHT(REGEXP_REPLACE(card_number, '[^0-9]', ''), 4))
    ELSE '****-****-****-****'
END;

-- Hash: SHA256 with version prefix
CREATE OR REPLACE FUNCTION catalog.schema.mask_hash(value STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN value IS NULL THEN NULL
    ELSE CONCAT('HASH_v1_', SUBSTRING(SHA2(CONCAT(value, ':v1'), 256), 1, 16))
END;

-- Redact: replace with [REDACTED]
CREATE OR REPLACE FUNCTION catalog.schema.mask_redact(value STRING)
RETURNS STRING
DETERMINISTIC
RETURN CASE
    WHEN value IS NULL THEN NULL
    ELSE '[REDACTED]'
END;
```

### Row Filter UDFs

Row filter UDFs return `BOOLEAN`: `TRUE` to include the row, `FALSE` to exclude it. Row filter UDFs used with FGAC must take **0 arguments** (unlike column masks which take 1).

```sql
-- Region-based filter: hide EU rows
CREATE OR REPLACE FUNCTION catalog.schema.is_not_eu_region(region_value STRING)
RETURNS BOOLEAN
DETERMINISTIC
RETURN CASE
    WHEN region_value IS NULL THEN TRUE
    WHEN LOWER(region_value) LIKE '%eu%' THEN FALSE
    WHEN LOWER(region_value) LIKE '%europe%' THEN FALSE
    ELSE TRUE
END;
```

---

## Step 4: FGAC Policies

Policies are scoped to a **catalog**, **schema**, or **table**. The clause `FOR TABLES` is always present. The `for_securable_type` is always `TABLE`.

### Column Mask Policy

```sql
-- Catalog level — masks matching columns in ALL tables in the catalog
CREATE OR REPLACE POLICY mask_pii_ssn
ON CATALOG my_catalog
COMMENT 'Mask SSN columns catalog-wide'
COLUMN MASK my_catalog.my_schema.mask_ssn
TO `analysts`, `data_scientists`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('pii_type', 'ssn') AS masked_col
ON COLUMN masked_col;

-- Schema level — masks matching columns in all tables in the schema
CREATE OR REPLACE POLICY mask_pii_ssn
ON SCHEMA my_catalog.my_schema
COMMENT 'Mask SSN columns in schema'
COLUMN MASK my_catalog.my_schema.mask_ssn
TO `analysts`, `data_scientists`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('pii_type', 'ssn') AS masked_col
ON COLUMN masked_col;

-- Table level — masks matching columns on a single table
CREATE OR REPLACE POLICY mask_pii_ssn
ON TABLE my_catalog.my_schema.my_table
COMMENT 'Mask SSN columns on specific table'
COLUMN MASK my_catalog.my_schema.mask_ssn
TO `analysts`, `data_scientists`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('pii_type', 'ssn') AS masked_col
ON COLUMN masked_col;

-- Cross-catalog UDF — UDF in governance catalog, policy on prod
CREATE OR REPLACE POLICY mask_ssn_finance
ON SCHEMA prod.finance
COMMENT 'Mask SSN using shared governance UDF'
COLUMN MASK governance.masking_udfs.mask_ssn
TO `analysts`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('pii_type', 'ssn') AS masked_col
ON COLUMN masked_col;

-- Match any column with a tag key (regardless of value)
CREATE OR REPLACE POLICY mask_all_pii
ON SCHEMA my_catalog.my_schema
COLUMN MASK my_catalog.my_schema.mask_full
TO `external_users`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTag('pii_type') AS masked_col
ON COLUMN masked_col;
```

### Row Filter Policy

```sql
-- Catalog level
CREATE OR REPLACE POLICY filter_eu_data
ON CATALOG my_catalog
COMMENT 'Filter EU rows catalog-wide'
ROW FILTER my_catalog.my_schema.is_not_eu_region
TO `us_team`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('region', 'eu') AS filter_col
USING COLUMNS (filter_col);

-- Schema level
CREATE OR REPLACE POLICY filter_eu_data
ON SCHEMA my_catalog.my_schema
COMMENT 'Filter EU rows in schema'
ROW FILTER my_catalog.my_schema.is_not_eu_region
TO `us_team`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('region', 'eu') AS filter_col
USING COLUMNS (filter_col);

-- Table level
CREATE OR REPLACE POLICY filter_eu_data
ON TABLE my_catalog.my_schema.my_table
COMMENT 'Filter EU rows on specific table'
ROW FILTER my_catalog.my_schema.is_not_eu_region
TO `us_team`
EXCEPT `gov_admin`
FOR TABLES
MATCH COLUMNS hasTagValue('region', 'eu') AS filter_col
USING COLUMNS (filter_col);
```

### Drop Policy

```sql
DROP POLICY mask_pii_ssn ON CATALOG my_catalog;
DROP POLICY mask_pii_ssn ON SCHEMA my_catalog.my_schema;
DROP POLICY mask_pii_ssn ON TABLE my_catalog.my_schema.my_table;
```

> There is no `ALTER POLICY`. To modify a policy's UDF, tag matching, or scope, drop and recreate it. Only principals and comment can be updated in-place via the SDK.

---

## Policy Quotas

| Scope | Max Policies |
|-------|-------------|
| Per Catalog | 10 |
| Per Schema | 10 |
| Per Table | 5 |

---

## SQL That Does NOT Exist

These SQL commands do **not** exist in Databricks. Do not use them.

| Invalid SQL | What to Use Instead |
|---|---|
| `SHOW POLICIES` | SDK: `w.policies.list_policies()` or MCP tool `list_fgac_policies` |
| `DESCRIBE POLICY` | SDK: `w.policies.get_policy()` or MCP tool `get_fgac_policy` |
| `ALTER POLICY` | Drop and recreate the policy |
| `ALTER USER SET ATTRIBUTES` | SCIM API for user attributes |

---

## Discovery Queries

```sql
-- List catalogs, schemas, tables
SHOW CATALOGS;
SHOW SCHEMAS IN my_catalog;
SHOW TABLES IN my_catalog.my_schema;

-- Describe table with extended metadata
DESCRIBE TABLE EXTENDED my_catalog.my_schema.my_table;

-- List UDFs in a schema
SHOW USER FUNCTIONS IN my_catalog.my_schema;

-- Describe a UDF
DESCRIBE FUNCTION EXTENDED my_catalog.my_schema.mask_ssn;

-- Column tags in a table
SELECT tag_name, tag_value, column_name
FROM system.information_schema.column_tags
WHERE catalog_name = 'my_catalog'
  AND schema_name = 'my_schema'
  AND table_name = 'my_table';
```

---

## Python SDK Reference

### Setup

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import (
    ColumnMaskOptions,
    MatchColumn,
    PolicyInfo,
    PolicyType,
    RowFilterOptions,
    SecurableType,
)

w = WorkspaceClient()  # Auto-detects credentials
```

### List Policies

```python
policies = list(w.policies.list_policies(
    on_securable_type="CATALOG",
    on_securable_fullname="my_catalog",
    include_inherited=True,
))

for p in policies:
    print(f"{p.name}: {p.policy_type} on {p.on_securable_fullname}")

# Filter by type
column_masks = [p for p in policies if p.policy_type == "COLUMN_MASK"]
row_filters = [p for p in policies if p.policy_type == "ROW_FILTER"]
```

### Get Policy

```python
policy = w.policies.get_policy(
    name="mask_pii_ssn",
    on_securable_type="SCHEMA",
    on_securable_fullname="my_catalog.my_schema",
)
```

### Create Column Mask Policy

```python
policy_info = PolicyInfo(
    name="mask_pii_ssn",
    policy_type=PolicyType.POLICY_TYPE_COLUMN_MASK,
    on_securable_type=SecurableType.SCHEMA,
    on_securable_fullname="my_catalog.my_schema",
    for_securable_type=SecurableType.TABLE,
    to_principals=["analysts", "data_scientists"],
    except_principals=["gov_admin"],
    comment="Mask SSN columns in schema",
    column_mask=ColumnMaskOptions(
        function_name="my_catalog.my_schema.mask_ssn",
        on_column="masked_col",
    ),
    match_columns=[
        MatchColumn(
            alias="masked_col",
            condition="hasTagValue('pii_type', 'ssn')",
        )
    ],
)
policy = w.policies.create_policy(policy_info=policy_info)
```

### Create Row Filter Policy

```python
policy_info = PolicyInfo(
    name="filter_eu_data",
    policy_type=PolicyType.POLICY_TYPE_ROW_FILTER,
    on_securable_type=SecurableType.SCHEMA,
    on_securable_fullname="my_catalog.my_schema",
    for_securable_type=SecurableType.TABLE,
    to_principals=["us_team"],
    except_principals=["gov_admin"],
    comment="Filter EU rows in schema",
    row_filter=RowFilterOptions(
        function_name="my_catalog.my_schema.is_not_eu_region",
    ),
    match_columns=[
        MatchColumn(
            alias="filter_col",
            condition="hasTagValue('region', 'eu')",
        )
    ],
)
policy = w.policies.create_policy(policy_info=policy_info)
```

### Update Policy

Only principals and comment can be updated. To change the UDF, tag matching, or scope, drop and recreate.

```python
update_info = PolicyInfo(
    to_principals=["analysts", "data_scientists", "new_team"],
    except_principals=["gov_admin", "senior_admins"],
    comment="Updated: added new_team",
    for_securable_type=SecurableType.TABLE,
    policy_type=PolicyType.POLICY_TYPE_COLUMN_MASK,
)
updated = w.policies.update_policy(
    name="mask_pii_ssn",
    on_securable_type="SCHEMA",
    on_securable_fullname="my_catalog.my_schema",
    policy_info=update_info,
    update_mask="to_principals,except_principals,comment",
)
```

### Delete Policy

```python
w.policies.delete_policy(
    name="mask_pii_ssn",
    on_securable_type="SCHEMA",
    on_securable_fullname="my_catalog.my_schema",
)
```

### Error Handling

```python
from databricks.sdk.errors import NotFound, PermissionDenied, BadRequest

try:
    policy = w.policies.get_policy(name="nonexistent", ...)
except NotFound:
    print("Policy not found")
except PermissionDenied:
    print("Insufficient permissions - need MANAGE on securable")
except BadRequest as e:
    print(f"Invalid request: {e}")
```

---

## MCP Tools Reference

All FGAC operations are exposed through a single MCP tool: `manage_uc_fgac_policies`. The `action` parameter selects the operation.

### Discovery Actions

| Action | Description | Key Parameters |
|--------|-------------|----------------|
| `list` | List policies on a securable | `securable_type`, `securable_fullname`, `include_inherited`, `policy_type` |
| `get` | Get a specific policy by name | `policy_name`, `securable_type`, `securable_fullname` |
| `get_table_policies` | Get column masks and row filters on a table | `catalog`, `schema`, `table` |
| `get_masking_functions` | List masking UDFs in a schema | `catalog`, `schema` (or `udf_catalog`, `udf_schema` for cross-catalog) |
| `check_quota` | Check policy quota on a securable | `securable_type`, `securable_fullname` |

### Preview Action (Human-in-the-Loop Gate)

| Action | Description | Key Parameters |
|--------|-------------|----------------|
| `preview` | Preview changes without executing; returns `approval_token` | `preview_action` (`CREATE`/`UPDATE`/`DELETE`), `policy_name`, `securable_type`, `securable_fullname`, plus policy params for CREATE |

### Mutation Actions (Require Approval Token)

| Action | Description | Key Parameters |
|--------|-------------|----------------|
| `create` | Create a new FGAC policy | `policy_name`, `policy_type`, `securable_type`, `securable_fullname`, `function_name`, `to_principals`, `tag_name`, `tag_value`, `approval_token` |
| `update` | Update policy principals or comment | `policy_name`, `securable_type`, `securable_fullname`, `to_principals`, `except_principals`, `comment`, `approval_token` |
| `delete` | Delete a policy | `policy_name`, `securable_type`, `securable_fullname`, `approval_token` |

---

## Human-in-the-Loop Governance Workflow

FGAC policies control who can see sensitive data like SSNs, emails, and salaries. Because misconfigured policies can expose private data or lock out administrators, all mutating operations go through a governed workflow with two safety gates.

### Why Human-in-the-Loop?

An AI agent that can freely create, change, or delete access control policies is dangerous. It could:

- Accidentally expose PII to the wrong group
- Remove masking from sensitive columns
- Lock administrators out of their own data

The human-in-the-loop pattern ensures **no policy change happens without explicit human approval**.

### The Two Safety Gates

#### Gate 1: Preview + Approval Token

Every mutating operation (create, update, delete) requires a two-step process:

1. **Preview** — The agent calls `preview_policy_changes()` which generates the exact SQL that *would* run, but **does not execute anything**. It also returns a cryptographic **approval token**.

2. **Execute** — Only after the human reviews and approves does the agent call the mutation (e.g., `create_fgac_policy()`), passing the approval token from the preview step.

The approval token is an **HMAC-SHA256 signed receipt** that binds the exact parameters from the preview to a timestamp:

| Protection | How It Works |
|-----------|--------------|
| Parameter tampering | The token encodes every parameter (policy name, type, principals, UDF, tags). If the agent passes different parameters at execution time, the signature won't match and the operation is rejected. |
| Replay attacks | The token includes a timestamp and **expires after 10 minutes**. Old approvals cannot be reused. |
| Token forgery | The token is signed with an HMAC secret (`FGAC_APPROVAL_SECRET`). Without the secret, a valid token cannot be forged. |

#### Gate 2: Admin Group Check

Every mutating operation also verifies that the current Databricks user belongs to the configured admin group (env var `FGAC_ADMIN_GROUP`, defaults to `admins`). Even with a valid approval token, a non-admin user cannot make changes.

### The 6-Step Workflow

```
ANALYZE --> RECOMMEND --> PREVIEW --> APPROVE --> EXECUTE --> VERIFY
   |            |            |           |           |          |
   v            v            v           v           v          v
 Discover    Generate     Show SQL    Human      Run SDK    Confirm
 current     policy       & impact    confirms   call w/    changes
 state       proposals    preview     changes    token      applied
```

#### Step 1: ANALYZE — Discover Current State

The agent gathers information without making any changes:

```
list_fgac_policies()      --> What policies already exist?
get_masking_functions()   --> What masking UDFs are available?
get_column_tags_api()     --> What columns are tagged with PII labels?
execute_sql(DESCRIBE)     --> What does the table schema look like?
```

#### Step 2: RECOMMEND — Generate Proposals

Based on the analysis, the agent identifies gaps and recommends new policies:

> "The `email` column is tagged `pii=email` but has no masking policy. I recommend creating a column mask policy using a `mask_email` UDF."

If a required UDF doesn't exist yet, the agent creates it first (UDF creation is a non-destructive SQL operation).

#### Step 3: PREVIEW — Human-in-the-Loop Gate

The agent calls `preview_policy_changes()` with the proposed parameters. **This does NOT execute anything.** It returns:

```json
{
  "success": true,
  "action": "CREATE",
  "preview": {
    "policy_name": "mask_email_for_non_admins",
    "equivalent_sql": "CREATE OR REPLACE POLICY mask_email_for_non_admins\nON SCHEMA ai_dev_kit_test.test_schema\n..."
  },
  "requires_approval": true,
  "approval_token": "da70b6c3...:<base64-encoded-params>"
}
```

The agent presents the equivalent SQL and impact summary to the human.

#### Step 4: APPROVE — Human Decision

The human reviews:
- The exact SQL that will run
- Which principals are affected
- Which columns/tables will be masked
- Any warnings

Then explicitly replies **"approve"** or requests changes.

#### Step 5: EXECUTE — Apply With Token

Only after approval, the agent passes the approval token to the mutation:

```python
create_fgac_policy(
    policy_name="mask_email_for_non_admins",
    policy_type="COLUMN_MASK",
    securable_type="SCHEMA",
    securable_fullname="ai_dev_kit_test.test_schema",
    function_name="ai_dev_kit_test.test_schema.mask_email",
    to_principals=["account users"],
    tag_name="pii",
    tag_value="email",
    approval_token="da70b6c3...:<base64-encoded-params>"
)
```

Internally, the function:
1. Checks admin group membership (`_check_admin_group()`)
2. Validates the approval token signature matches the parameters
3. Verifies the token hasn't expired (10-minute TTL)
4. Only then calls the Databricks SDK to create the policy

#### Step 6: VERIFY — Confirm Changes

The agent verifies the policy was applied correctly:

```python
get_fgac_policy(policy_name="mask_email_for_non_admins", ...)
execute_sql("SELECT email FROM employee_pii LIMIT 5")
# Expected: a***@acme.com, b***@acme.com, etc.
```

### Sequence Diagram

```
Agent                           Human                       Databricks
  |                               |                              |
  |--- preview(CREATE, ...) -----------------------------------> |
  |<-- SQL + approval_token ------------------------------------ |
  |                               |                              |
  |--- "Here's what I'll do:" --> |                              |
  |    [shows SQL + details]      |                              |
  |                               |                              |
  |<-- "approve" ---------------- |                              |
  |                               |                              |
  |--- create(... token) --------------------------------------> |
  |    [1] check admin group      |                              |
  |    [2] verify token signature |                              |
  |    [3] verify params match    |                              |
  |    [4] verify not expired     |                              |
  |<-- policy created ------------------------------------------ |
  |                               |                              |
  |--- verify(get_policy) --------------------------------------> |
  |<-- confirmed ------------------------------------------------ |
```

---

## Approval Token Internals

### Token Structure

```
<hmac-sha256-signature>:<base64-encoded-json-payload>
```

Example:
```
da70b6c3455944a3...:eyJhY3Rpb24iOiAiQ1JFQVRFIiwgInBvbGljeV9uYW1lIjog...
```

### Generation (during preview)

```python
def _generate_approval_token(params: dict) -> str:
    # 1. Remove null values, add current timestamp
    clean_params = {k: v for k, v in params.items() if v is not None}
    clean_params["timestamp"] = int(time.time())

    # 2. Serialize to deterministic JSON (sorted keys for consistency)
    payload = json.dumps(clean_params, sort_keys=True)

    # 3. Sign with HMAC-SHA256
    signature = hmac.new(
        APPROVAL_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    # 4. Encode payload as base64
    b64_payload = base64.b64encode(payload.encode()).decode()

    return f"{signature}:{b64_payload}"
```

### Validation (during execute)

```python
def _validate_approval_token(approval_token: str, current_params: dict) -> None:
    # 1. Split token into signature and payload
    signature, b64_payload = approval_token.split(":", 1)

    # 2. Decode payload and re-compute expected signature
    payload = base64.b64decode(b64_payload).decode()
    expected_sig = hmac.new(
        APPROVAL_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    # 3. Verify signature matches (constant-time comparison)
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Invalid or expired approval token")

    # 4. Check timestamp (10-minute TTL)
    token_data = json.loads(payload)
    ts = token_data.pop("timestamp", 0)
    if abs(time.time() - ts) > 600:
        raise ValueError("Invalid or expired approval token")

    # 5. Verify all parameters match what was previewed
    if token_data != current_params:
        raise ValueError("Invalid or expired approval token")
```

### Token Payload Example

For a CREATE action, the token payload contains:

```json
{
  "action": "CREATE",
  "policy_name": "mask_email_for_non_admins",
  "policy_type": "COLUMN_MASK",
  "securable_type": "SCHEMA",
  "securable_fullname": "ai_dev_kit_test.test_schema",
  "function_name": "ai_dev_kit_test.test_schema.mask_email",
  "to_principals": ["account users"],
  "tag_name": "pii",
  "tag_value": "email",
  "comment": "Masks email columns for all non-admin users",
  "timestamp": 1770853648
}
```

Every single field must match between preview and execution, or the token is rejected.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FGAC_APPROVAL_SECRET` | `fgac-default-dev-secret` | HMAC secret for signing approval tokens. **Set to a strong random value in production.** |
| `FGAC_ADMIN_GROUP` | `admins` | Databricks group required for mutating operations. |

---

## Threat Model

| Attack Vector | Protection |
|--------------|-----------|
| Agent changes parameters after human approval | Token signature binds exact params; mismatch = rejected |
| Stale approval reused hours/days later | Token expires after 10 minutes |
| Non-admin user attempts policy mutation | `_check_admin_group()` verifies group membership |
| Token forged without the signing secret | HMAC-SHA256 verification fails |
| Timing attack on signature comparison | `hmac.compare_digest()` uses constant-time comparison |

---

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `POLICY_QUOTA_EXCEEDED` | Too many policies on scope | Consolidate policies or use broader scope |
| `INVALID_TAG_VALUE` | Tag value not in governed tag's allowed values | Check governed tag configuration in UI |
| `UDF_NOT_FOUND` | Masking UDF doesn't exist | Create UDF first, use fully qualified name |
| `POLICY_ALREADY_EXISTS` | Policy name conflict | Use `CREATE OR REPLACE POLICY` or delete existing first |
| `INSUFFICIENT_PERMISSIONS` | Missing `MANAGE` on securable | Grant `MANAGE` permission to policy creator |
| `SHOW POLICIES is not supported` | Used invalid SQL | Use SDK `w.policies.list_policies()` instead |
| `Could not find principal` | Principal group doesn't exist in workspace | Verify group name exists in account/workspace |
| `Invalid or expired approval token` | Token expired, params changed, or forged | Re-run preview to get a fresh token |

---

## Best Practices

1. **Use governed tags** (not ad-hoc tags) for FGAC policy matching
2. **Always include an admin exception** (`EXCEPT \`gov_admin\``) in every policy to prevent lockout
3. **Use deterministic UDFs** with simple CASE statements — no external calls or nested UDFs
4. **Preview before executing** any policy change — never auto-execute
5. **Start at schema scope** and narrow to table only when needed
6. **Name policies descriptively**: `mask_{what}_{scope}` or `filter_{what}_{scope}`
7. **Test UDFs independently** before binding to policies (e.g., `SELECT mask_ssn('123-45-6789')`)
8. **Monitor policy quotas** — consolidate when approaching limits (10 per catalog/schema, 5 per table)
9. **Set `FGAC_APPROVAL_SECRET`** to a strong random value in production
10. **Grant to groups, not users** — easier to manage and audit

---

## Source Files

| File | Description |
|------|-------------|
| `databricks-tools-core/databricks_tools_core/unity_catalog/fgac_policies.py` | Core implementation (token generation, validation, CRUD) |
| `databricks-mcp-server/databricks_mcp_server/tools/fgac_policies.py` | MCP tool dispatcher (routes actions to core functions) |
| `databricks-tools-core/tests/integration/unity_catalog/test_fgac_policies.py` | Integration tests |
| `ai-dev-project/.claude/skills/databricks-unity-catalog/7-fgac-overview.md` | FGAC workflow overview and SQL syntax |
| `ai-dev-project/.claude/skills/databricks-unity-catalog/8-fgac-sql-generation.md` | SQL generation reference |
| `ai-dev-project/.claude/skills/databricks-unity-catalog/9-fgac-sdk-and-tools.md` | SDK patterns and MCP tool reference |
