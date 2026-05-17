---
name: databricks-unity-catalog
description: "Unity Catalog governance and fine-grained access control (FGAC). Use when the user wants to restrict row access, mask or redact columns, hide sensitive data, set up PII protection, configure who can see what, implement row-level or column-level security, work with ABAC policies, governed tags, data classification, object privileges (GRANT/REVOKE), or migrate from dynamic views or traditional row filters to ABAC. Also use for system tables (audit, lineage, billing) and volume file operations."
---

# Unity Catalog

Guidance for Unity Catalog governance, fine-grained access control (FGAC), ABAC policies, object privileges, system tables, volumes, and data profiling.

## When to Use This Skill

Use this skill when:
- Implementing **ABAC policies** (attribute-based row filters and column masks driven by governed tags)
- Managing **governed tags** (create, apply, and maintain tag taxonomy for ABAC)
- Setting up **data classification** (AI-powered PII and sensitive data detection)
- Working with **Fine-Grained Access Control (FGAC)** — traditional per-table or ABAC approach
- Configuring **object privileges** (GRANT/REVOKE on catalogs, schemas, tables, functions)
- **Migrating** from traditional per-table row filters/column masks to ABAC policies
- **Migrating** from dynamic views used for row/column security to ABAC policies
- Working with **volumes** (upload, download, list files in `/Volumes/`)
- Querying **lineage** (table dependencies, column-level lineage)
- Analyzing **audit logs** (who accessed what, permission changes)
- Monitoring **billing and usage** (DBU consumption, cost analysis)
- Tracking **compute resources** (cluster usage, warehouse metrics)
- Reviewing **job execution** (run history, success rates, failures)
- Analyzing **query performance** (slow queries, warehouse utilization)
- Profiling **data quality** (data profiling, drift detection, metric tables)

## Reference Files

| Topic | File | Description |
|-------|------|-------------|
| UC ACLs | [uc-acls.md](uc-acls.md) | Read when setting up GRANT/REVOKE, troubleshooting access errors, or before any ABAC work — prerequisite |
| ABAC Overview | [abac-overview.md](abac-overview.md) | Read when starting an ABAC implementation or deciding between ABAC, traditional filters, and dynamic views |
| Governed Tags | [abac-governed-tags.md](abac-governed-tags.md) | Read when creating, applying, or managing governed tags, or setting up a tag taxonomy |
| Traditional Row Filters & Column Masks | [traditional-row-filters-and-column-masks.md](traditional-row-filters-and-column-masks.md) | Read when working with ALTER TABLE SET ROW FILTER / SET MASK, or migrating traditional filters to ABAC |
| Dynamic Views | [uc-dynamic-views.md](uc-dynamic-views.md) | Read when working with or migrating security-bearing dynamic views to ABAC policies |
| ABAC Policies | [abac-policies.md](abac-policies.md) | Read when creating, editing, or troubleshooting ABAC row filter or column mask policies |
| Data Classification | [abac-data-classification.md](abac-data-classification.md) | Read when enabling AI-powered PII detection or using classification results to drive ABAC policy recommendations |
| ABAC Patterns | [abac-patterns.md](abac-patterns.md) | Read when building UDFs for ABAC, looking for end-to-end walkthroughs, or optimizing filter/mask performance |
| System Tables | [5-system-tables.md](5-system-tables.md) | Lineage, audit, billing, compute, jobs, query history |
| Volumes | [6-volumes.md](6-volumes.md) | Volume file operations, permissions, best practices |
| Data Profiling | [7-data-profiling.md](7-data-profiling.md) | Data profiling, drift detection, profile metrics |

## Quick Start

### Volume File Operations (MCP Tools)

| Tool | Usage |
|------|-------|
| `list_volume_files` | `list_volume_files(volume_path="/Volumes/catalog/schema/volume/path/")` |
| `get_volume_folder_details` | `get_volume_folder_details(volume_path="catalog/schema/volume/path", format="parquet")` - schema, row counts, stats |
| `upload_to_volume` | `upload_to_volume(local_path="/tmp/data/*", volume_path="/Volumes/.../dest")` |
| `download_from_volume` | `download_from_volume(volume_path="/Volumes/.../file.csv", local_path="/tmp/file.csv")` |
| `create_volume_directory` | `create_volume_directory(volume_path="/Volumes/.../new_folder")` |

### Enable System Tables Access

```sql
-- Grant access to system tables
GRANT USE CATALOG ON CATALOG system TO `data_engineers`;
GRANT USE SCHEMA ON SCHEMA system.access TO `data_engineers`;
GRANT SELECT ON SCHEMA system.access TO `data_engineers`;
```

### Common Queries

```sql
-- Table lineage: What tables feed into this table?
SELECT source_table_full_name, source_column_name
FROM system.access.table_lineage
WHERE target_table_full_name = 'catalog.schema.table'
  AND event_date >= current_date() - 7;

-- Audit: Recent permission changes
SELECT event_time, user_identity.email, action_name, request_params
FROM system.access.audit
WHERE action_name LIKE '%GRANT%' OR action_name LIKE '%REVOKE%'
ORDER BY event_time DESC
LIMIT 100;

-- Billing: DBU usage by workspace
SELECT workspace_id, sku_name, SUM(usage_quantity) AS total_dbus
FROM system.billing.usage
WHERE usage_date >= current_date() - 30
GROUP BY workspace_id, sku_name;
```

## MCP Tool Integration

Use `mcp__databricks__execute_sql` for system table queries:

```python
# Query lineage
mcp__databricks__execute_sql(
    sql_query="""
        SELECT source_table_full_name, target_table_full_name
        FROM system.access.table_lineage
        WHERE event_date >= current_date() - 7
    """,
    catalog="system"
)
```

## Best Practices

1. **Filter by date** - System tables can be large; always use date filters
2. **Use appropriate retention** - Check your workspace's retention settings
3. **Grant minimal access** - System tables contain sensitive metadata
4. **Schedule reports** - Create scheduled queries for regular monitoring

## Related Skills

- **[databricks-spark-declarative-pipelines](../databricks-spark-declarative-pipelines/SKILL.md)** - for pipelines that write to Unity Catalog tables
- **[databricks-jobs](../databricks-jobs/SKILL.md)** - for job execution data visible in system tables
- **[databricks-synthetic-data-gen](../databricks-synthetic-data-gen/SKILL.md)** - for generating data stored in Unity Catalog Volumes
- **[databricks-aibi-dashboards](../databricks-aibi-dashboards/SKILL.md)** - for building dashboards on top of Unity Catalog data

## Resources

- [Unity Catalog System Tables](https://docs.databricks.com/administration-guide/system-tables/)
- [Audit Log Reference](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html)
