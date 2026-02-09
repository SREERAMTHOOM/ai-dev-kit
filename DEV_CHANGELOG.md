# Dev Changelog — Unity Catalog ABAC Policy Governance

**Branch**: `feature/uc_abac_skills`
**Date**: 2026-02-09
**Author**: sreeramreddy.thoom
**Reference**: UCABAC repo (`/Users/sreeramreddy.thoom/Documents/ClaudeCodeRepo/UCABAC`)

---

## Overview

Adds a new **`uc-abac-governance`** Claude Code skill to the Databricks AI Dev Kit, providing comprehensive guidance for managing Attribute-Based Access Control (ABAC) policies in Unity Catalog. Also adds Python SDK examples for ABAC policy operations.

The skill content is derived from the UCABAC project — a production ABAC governance agent with multi-agent architecture, MCP server, and React frontend.

**Excluded:** Policy drift detection is intentionally omitted from this skill.

---

## New Files

### Skill: `uc-abac-governance`

| File | Description |
|------|-------------|
| `databricks-skills/uc-abac-governance/SKILL.md` | Main skill: ABAC overview, governed tags, tag assignments, masking UDFs, CREATE/DROP POLICY syntax, human-in-the-loop workflow, policy quotas, invalid SQL warnings, common errors |
| `databricks-skills/uc-abac-governance/sql-generation.md` | SQL patterns: SET/UNSET TAG (legacy + modern), CREATE FUNCTION for masking UDFs (full, partial, hash, redact, nullify, SSN, email, credit card), row filter UDFs, CREATE/DROP POLICY, tag discovery queries, enums reference |
| `databricks-skills/uc-abac-governance/python-sdk-patterns.md` | Python SDK: `w.policies.list_policies()`, `create_policy()`, `get_policy()`, `update_policy()`, `delete_policy()`, error handling, quota checking, async patterns |
| `databricks-skills/uc-abac-governance/mcp-tools-reference.md` | MCP tool reference: 12 tools — `list_abac_policies`, `get_abac_policy`, `create_abac_policy`, `update_abac_policy`, `delete_abac_policy`, `preview_policy_changes`, `get_table_policies`, `get_column_tags_api`, `get_masking_functions`, `get_schema_info`, `get_catalog_info`, `list_table_policies_in_schema` |

### Installed Skills (mirrors of above)

| File | Description |
|------|-------------|
| `.claude/skills/uc-abac-governance/SKILL.md` | Installed copy |
| `.claude/skills/uc-abac-governance/sql-generation.md` | Installed copy |
| `.claude/skills/uc-abac-governance/python-sdk-patterns.md` | Installed copy |
| `.claude/skills/uc-abac-governance/mcp-tools-reference.md` | Installed copy |

### SDK Example

| File | Description |
|------|-------------|
| `databricks-skills/databricks-python-sdk/examples/6-abac-policies.py` | Python SDK example: list, create, get, update, delete ABAC policies with error handling |

---

## Modified Files

| File | Change |
|------|--------|
| `databricks-skills/install_skills.sh` | Added `uc-abac-governance` to `DATABRICKS_SKILLS`, `get_skill_description()`, and `get_skill_extra_files()`. Updated `databricks-python-sdk` extra files to include `examples/6-abac-policies.py`. |
| `databricks-skills/databricks-python-sdk/SKILL.md` | Added ABAC Policies section with SDK examples for list, get, create, update, delete operations |

---

## Key Design Decisions

### 1. Separate Skill vs. Extending `databricks-unity-catalog`

Created a **new dedicated skill** (`uc-abac-governance`) rather than extending the existing `databricks-unity-catalog` skill because:
- ABAC governance is a distinct, complex domain with its own workflow
- The existing UC skill focuses on system tables and volumes — different audience
- Separate skill allows targeted installation (`install_skills.sh uc-abac-governance`)
- Content volume warrants its own skill (4 reference files)

### 2. SQL Generation + SDK Dual Approach

The skill documents both approaches:
- **SQL generation**: `CREATE POLICY` / `DROP POLICY` syntax for SQL-based workflows
- **Python SDK**: `w.policies.*` methods for programmatic policy management
- MCP tool wrappers that combine both approaches

### 3. Human-in-the-Loop Workflow

The skill emphasizes a 6-step governance workflow matching the UCABAC agent pattern:
1. **Analyze** — scan table structure, existing tags, current policies
2. **Recommend** — generate policy recommendations based on tags
3. **Preview** — show proposed changes (SQL equivalent + impact)
4. **Approve** — human reviews and approves/rejects
5. **Execute** — create ABAC policies via SDK
6. **Verify** — confirm policies are active and masking works

### 4. `gov_admin` Safety Net

All examples enforce the `gov_admin` exception pattern — every ABAC policy must exclude the administrator group from masking/filtering.

---

## Source Mapping (UCABAC → ai-dev-kit)

| UCABAC Source | Skill Target |
|--------------|-------------|
| `ucabac/skills/governance-policy/SKILL.md` | `SKILL.md` |
| `ucabac/sql_gen/policy_skills.py` | `sql-generation.md` |
| `ucabac/sql_gen/tag_skills.py` | `sql-generation.md` |
| `ucabac/sql_gen/udf_skills.py` | `sql-generation.md` |
| `ucabac/sql_gen/_base.py` | `sql-generation.md` (enums) |
| `ucabac/mcp/policy_api_tools.py` | `mcp-tools-reference.md`, `python-sdk-patterns.md` |
| `ucabac/services/unity_catalog_client.py` | `python-sdk-patterns.md` |
| `ucabac/services/abac_policy_sync.py` | `python-sdk-patterns.md` |
| `ucabac/core/policy_manager.py` | `SKILL.md` (workflow) |
| `ucabac/skills/governance-policy/references/SQL_GEN.md` | `sql-generation.md` |
| `ucabac/skills/governance-policy/references/MCP_TOOLS.md` | `mcp-tools-reference.md` |

---

## Dependencies

- Databricks Runtime 16.1+ (for modern SET TAG syntax) or any version (for legacy syntax)
- Unity Catalog enabled workspace
- `databricks-sdk` (for `w.policies.*` API)
- MANAGE permission on target securables
- Governed tags created via Databricks UI (cannot be created via SQL)

---

## Testing Checklist

- [ ] `install_skills.sh --list` shows `uc-abac-governance` with correct description
- [ ] `install_skills.sh uc-abac-governance --local` installs all 4 files
- [ ] SKILL.md frontmatter has valid `name` and `description`
- [ ] SQL examples match Databricks ABAC documentation syntax
- [ ] Python SDK example parses without syntax errors
- [ ] No references to invalid SQL (SHOW POLICIES, DESCRIBE POLICY, etc.)
- [ ] All policies include `gov_admin` in EXCEPT clause
