# FGAC Human-in-the-Loop Guardrails

Fine-Grained Access Control (FGAC) policy mutations (create, update, delete) are protected by two programmatic guardrails that ensure every change is previewed, approved, and executed by an authorized user.

---

## Architecture Overview

```
                          +------------------+
                          |   Human / Agent  |
                          +--------+---------+
                                   |
                          1. Request change
                                   |
                                   v
                     +----------------------------+
                     |   preview_policy_changes()  |
                     |                            |
                     |  - Validates parameters    |
                     |  - Generates SQL preview   |
                     |  - Signs params + timestamp |
                     |    with HMAC-SHA256        |
                     |  - Returns approval_token  |
                     +-------------+--------------+
                                   |
                     2. Preview + approval_token
                                   |
                                   v
                     +----------------------------+
                     |    Human Reviews Preview    |
                     |                            |
                     |  - Equivalent SQL shown    |
                     |  - Warnings displayed      |
                     |  - Approves or rejects     |
                     +-------------+--------------+
                                   |
                          3. "Approve" + token
                                   |
                                   v
                     +----------------------------+
                     |  create/update/delete_*()   |
                     |                            |
                     |  +-- Admin Group Check --+ |
                     |  |  w.current_user.me()  | |
                     |  |  Is user in group?    | |
                     |  +---------+-------------+ |
                     |            | Yes            |
                     |            v                |
                     |  +-- Token Validation ---+ |
                     |  |  Verify HMAC sig      | |
                     |  |  Check TTL (10 min)   | |
                     |  |  Match params         | |
                     |  +---------+-------------+ |
                     |            | Valid          |
                     |            v                |
                     |     Execute SDK call        |
                     +----------------------------+
```

---

## Guardrail 1: Approval Token

Every mutating call **requires** a cryptographic token obtained from `preview_policy_changes()`. This prevents any create/update/delete from executing without a prior preview step.

### Token Lifecycle

```
  preview_policy_changes(action="CREATE", policy_name="mask_ssn", ...)
         |
         |  1. Collect parameters
         |  2. Add timestamp = now()
         |  3. JSON serialize (sorted keys)
         |  4. HMAC-SHA256(secret, payload) -> signature
         |  5. Return "signature:base64(payload)"
         |
         v
  approval_token = "a3f8c1...:eyJhY3Rpb24iOiJDUkVBVEUi..."
         |
         |  Token is valid for 10 minutes
         |  Token is bound to exact parameters
         |
         v
  create_fgac_policy(..., approval_token=token)
         |
         |  1. Split token -> signature + payload
         |  2. Recompute HMAC, compare (constant-time)
         |  3. Decode payload, check timestamp within TTL
         |  4. Verify params match (action, policy_name, etc.)
         |  5. Reject on any mismatch
         |
         v
     Execute or Reject
```

### What the Token Binds

The token cryptographically binds these fields:

| Field | Purpose |
|-------|---------|
| `action` | CREATE, UPDATE, or DELETE |
| `policy_name` | Prevents using token A's preview for policy B |
| `securable_type` | CATALOG, SCHEMA, or TABLE |
| `securable_fullname` | The target securable |
| `policy_type` | COLUMN_MASK or ROW_FILTER (CREATE only) |
| `to_principals` | Who the policy applies to |
| `function_name` | The masking UDF (CREATE only) |
| `tag_name` / `tag_value` | Tag match condition (CREATE only) |
| `timestamp` | Ensures token expires after TTL |

### Rejection Scenarios

```
  Token from preview with policy_name="A"
  Used in create with policy_name="B"
         --> ValueError: "Invalid or expired approval token"

  Token generated 15 minutes ago (TTL = 10 min)
         --> ValueError: "Invalid or expired approval token"

  Token string tampered with or fabricated
         --> ValueError: "Invalid or expired approval token"

  No token provided at all
         --> TypeError (missing required argument)
```

---

## Guardrail 2: Admin Group Check

Before validating the token, the system verifies the caller belongs to a configurable admin group.

```
  Mutating call received
         |
         v
  +-----------------------------+
  |  w.current_user.me()        |
  |  Extract group memberships  |
  +-------------+---------------+
                |
       +--------+--------+
       |                  |
   "admins" in        "admins" not
   user.groups        in user.groups
       |                  |
       v                  v
   Continue to       PermissionError:
   token check       "User 'x' is not a member
                      of admin group 'admins'"
```

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `FGAC_APPROVAL_SECRET` | `fgac-default-dev-secret` | HMAC signing secret |
| `FGAC_ADMIN_GROUP` | `admins` | Required group for mutations |

> **Production**: Always set `FGAC_APPROVAL_SECRET` to a strong random value. The default is only suitable for development.

Token TTL is set to **600 seconds (10 minutes)** via `_TOKEN_TTL_SECONDS` in the source.

---

## End-to-End Workflow

### Happy Path

```
 Agent                          System                         Databricks
   |                              |                                |
   |  1. preview(CREATE, ...)     |                                |
   |----------------------------->|                                |
   |                              |  Generate token                |
   |  <-- preview + token --------|                                |
   |                              |                                |
   |  2. Show preview to human    |                                |
   |  3. Human says "approve"     |                                |
   |                              |                                |
   |  4. create(..., token)       |                                |
   |----------------------------->|                                |
   |                              |  Check admin group             |
   |                              |  Validate token                |
   |                              |  create_policy() ------------->|
   |                              |                                |
   |  <-- success + policy -------|  <-- policy created -----------|
   |                              |                                |
```

### Rejection Path (Mismatched Params)

```
 Agent                          System
   |                              |
   |  1. preview(CREATE, name=A)  |
   |----------------------------->|
   |  <-- token_A ----------------|
   |                              |
   |  2. create(name=B, token_A)  |
   |----------------------------->|
   |                              |  Check admin group -> OK
   |                              |  Validate token:
   |                              |    name=B != name=A in token
   |  <-- ValueError -------------|
   |                              |
```

### Rejection Path (Not an Admin)

```
 Agent                          System                     Databricks
   |                              |                            |
   |  1. preview(CREATE, ...)     |                            |
   |----------------------------->|                            |
   |  <-- token ------------------|                            |
   |                              |                            |
   |  2. create(..., token)       |                            |
   |----------------------------->|                            |
   |                              |  me() ------------------->|
   |                              |  <-- user (no admin grp) -|
   |  <-- PermissionError --------|                            |
   |                              |                            |
```

---

## Code Locations

| Component | File |
|-----------|------|
| Core guardrail functions | `databricks-tools-core/.../unity_catalog/fgac_policies.py` |
| MCP tool wrapper | `databricks-mcp-server/.../tools/fgac_policies.py` |
| Integration tests | `databricks-tools-core/tests/integration/unity_catalog/test_fgac_policies.py` |
| Skill docs | `databricks-skills/databricks-unity-catalog/9-fgac-sdk-and-tools.md` |

### Key Functions

| Function | Purpose |
|----------|---------|
| `_generate_approval_token(params)` | Signs preview params into a token |
| `_validate_approval_token(token, params)` | Verifies signature, TTL, and param match |
| `_check_admin_group()` | Verifies caller is in the admin group |
| `preview_policy_changes()` | Returns preview + `approval_token` |
| `create_fgac_policy(approval_token=...)` | Guarded policy creation |
| `update_fgac_policy(approval_token=...)` | Guarded policy update |
| `delete_fgac_policy(approval_token=...)` | Guarded policy deletion |

---

## FAQ

**Q: Can I skip the preview step and call create directly?**
No. `approval_token` is a required positional argument. Calling without it raises `TypeError`.

**Q: Can I reuse a token for multiple operations?**
No. Each token is bound to exact parameters. A token for policy A cannot create policy B.

**Q: What happens if my token expires?**
Call `preview_policy_changes()` again to get a fresh token. Tokens expire after 10 minutes.

**Q: Does the admin check apply to read operations?**
No. Only `create`, `update`, and `delete` require admin membership. Discovery functions (`list`, `get`, `preview`) are unrestricted.

**Q: How do I change the admin group?**
Set the `FGAC_ADMIN_GROUP` environment variable before starting the application.
