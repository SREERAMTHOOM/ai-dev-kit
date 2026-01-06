---
name: sdp
description: "Create, configure, or update Databricks' Lakeflow Spark Declarative Pipelines (SDP), also known as LDP, or historically Delta Live Tables (DLT). User should guide on using SQL or Python syntax."
---

# Lakeflow Spark Declarative Pipelines (SDP)

## Official Documentation

- **[Lakeflow Spark Declarative Pipelines Overview](https://docs.databricks.com/aws/en/ldp/)** - Main documentation hub
- **[SQL Language Reference](https://docs.databricks.com/aws/en/ldp/developer/sql-dev)** - SQL syntax for streaming tables and materialized views
- **[Python Language Reference](https://docs.databricks.com/aws/en/ldp/developer/python-ref)** - `pyspark.pipelines` API
- **[Loading Data](https://docs.databricks.com/aws/en/ldp/load)** - Auto Loader, Kafka, Kinesis ingestion
- **[Change Data Capture (CDC)](https://docs.databricks.com/aws/en/ldp/cdc)** - AUTO CDC, SCD Type 1/2
- **[Developing Pipelines](https://docs.databricks.com/aws/en/ldp/develop)** - File structure, testing, validation
- **[Liquid Clustering](https://docs.databricks.com/aws/en/delta/clustering)** - Modern data layout optimization

---

## Development Workflow with MCP Tools

Use MCP tools to create, run, and iterate on SDP pipelines. The **primary tool is `create_or_update_pipeline`** which handles the entire lifecycle.

### Step 1: Write Pipeline Files Locally

Create `.sql` or `.py` files in a local folder:

```
my_pipeline/
├── bronze/
│   └── ingest_orders.sql
├── silver/
│   └── clean_orders.sql
└── gold/
    └── daily_summary.sql
```

**Example bronze layer** (`bronze/ingest_orders.sql`):
```sql
CREATE OR REFRESH STREAMING TABLE bronze_orders
CLUSTER BY (order_date)
AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  _metadata.file_path AS _source_file
FROM read_files(
  '/Volumes/catalog/schema/raw/orders/',
  format => 'json',
  schemaHints => 'order_id STRING, customer_id STRING, amount DECIMAL(10,2), order_date DATE'
);
```

### Step 2: Upload to Databricks Workspace

```python
# MCP Tool: upload_folder
upload_folder(
    local_folder="/path/to/my_pipeline",
    workspace_folder="/Workspace/Users/user@example.com/my_pipeline"
)
```

### Step 3: Create/Update and Run Pipeline

Use **`create_or_update_pipeline`** - the main entry point. It:
1. Searches for an existing pipeline with the same name
2. Creates a new pipeline or updates the existing one
3. Optionally starts a pipeline run
4. Optionally waits for completion and returns detailed results

```python
# MCP Tool: create_or_update_pipeline
result = create_or_update_pipeline(
    name="my_orders_pipeline",
    root_path="/Workspace/Users/user@example.com/my_pipeline",
    catalog="my_catalog",
    schema="my_schema",
    workspace_file_paths=[
        "/Workspace/Users/user@example.com/my_pipeline/bronze/ingest_orders.sql",
        "/Workspace/Users/user@example.com/my_pipeline/silver/clean_orders.sql",
        "/Workspace/Users/user@example.com/my_pipeline/gold/daily_summary.sql"
    ],
    start_run=True,           # Start immediately
    wait_for_completion=True, # Wait and return final status
    full_refresh=True,        # Full refresh all tables
    timeout=1800              # 30 minute timeout
)
```

**Result contains actionable information:**
```python
{
    "success": True,                    # Did the operation succeed?
    "pipeline_id": "abc-123",           # Pipeline ID for follow-up operations
    "pipeline_name": "my_orders_pipeline",
    "created": True,                    # True if new, False if updated
    "state": "COMPLETED",               # COMPLETED, FAILED, TIMEOUT, etc.
    "catalog": "my_catalog",            # Target catalog
    "schema": "my_schema",              # Target schema
    "duration_seconds": 45.2,           # Time taken
    "message": "Pipeline created and completed successfully in 45.2s. Tables written to my_catalog.my_schema",
    "error_message": None,              # Error summary if failed
    "errors": []                        # Detailed error list if failed
}
```

### Step 4: Handle Results

**On Success:**
```python
if result["success"]:
    # Verify output tables
    stats = get_table_details(
        catalog="my_catalog",
        schema="my_schema",
        table_names=["bronze_orders", "silver_orders", "gold_daily_summary"]
    )
```

**On Failure:**
```python
if not result["success"]:
    # Message includes suggested next steps
    print(result["message"])
    # "Pipeline created but run failed. State: FAILED. Error: Column 'amount' not found.
    #  Use get_pipeline_events(pipeline_id='abc-123') for full details."

    # Get detailed errors
    events = get_pipeline_events(pipeline_id=result["pipeline_id"], max_results=50)
```

### Step 5: Iterate Until Working

1. Review errors from result or `get_pipeline_events`
2. Fix issues in local files
3. Re-upload with `upload_folder`
4. Run `create_or_update_pipeline` again (it will update, not recreate)
5. Repeat until `result["success"] == True`

---

## Quick Reference: MCP Tools

### Primary Tool

| Tool | Description |
|------|-------------|
| **`create_or_update_pipeline`** | **Main entry point.** Creates or updates pipeline, optionally runs and waits. Returns detailed status with `success`, `state`, `errors`, and actionable `message`. |

### Pipeline Management

| Tool | Description |
|------|-------------|
| `find_pipeline_by_name` | Find existing pipeline by name, returns pipeline_id |
| `get_pipeline` | Get pipeline configuration and current state |
| `start_update` | Start pipeline run (`validate_only=True` for dry run) |
| `get_update` | Poll update status (QUEUED, RUNNING, COMPLETED, FAILED) |
| `stop_pipeline` | Stop a running pipeline |
| `get_pipeline_events` | Get error messages for debugging failed runs |
| `delete_pipeline` | Delete a pipeline |

### Supporting Tools

| Tool | Description |
|------|-------------|
| `upload_folder` | Upload local folder to workspace (parallel) |
| `get_table_details` | Verify output tables have expected schema and row counts |
| `execute_sql` | Run ad-hoc SQL to inspect data |

---

## Core SQL Patterns

All examples use Unity Catalog: `catalog.schema.table`

### Bronze Layer (Ingestion)

```sql
CREATE OR REFRESH STREAMING TABLE bronze_orders
CLUSTER BY (order_date)
AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  _metadata.file_path AS _source_file
FROM read_files(
  '/Volumes/catalog/schema/raw/orders/',
  format => 'json',
  schemaHints => 'order_id STRING, amount DECIMAL(10,2), order_date DATE'
);
```

### Silver Layer (Cleansing with Expectations)

```sql
CREATE OR REFRESH STREAMING TABLE silver_orders (
  CONSTRAINT valid_order_id EXPECT (order_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_amount EXPECT (amount > 0) ON VIOLATION DROP ROW
)
CLUSTER BY (customer_id, order_date)
AS
SELECT
  order_id,
  customer_id,
  CAST(order_date AS DATE) AS order_date,
  CAST(amount AS DECIMAL(10,2)) AS amount
FROM STREAM bronze_orders;
```

### Gold Layer (Aggregation)

```sql
CREATE OR REFRESH MATERIALIZED VIEW gold_daily_sales
CLUSTER BY (order_day)
AS
SELECT
  date_trunc('day', order_date) AS order_day,
  COUNT(DISTINCT order_id) AS order_count,
  SUM(amount) AS daily_sales
FROM silver_orders
GROUP BY date_trunc('day', order_date);
```

### SCD Type 2 (History Tracking)

```sql
CREATE OR REFRESH STREAMING TABLE customers_history;

CREATE FLOW customers_cdc_flow AS
AUTO CDC INTO customers_history
FROM STREAM customers_cdc_source
KEYS (customer_id)
SEQUENCE BY event_timestamp
STORED AS SCD TYPE 2
TRACK HISTORY ON *;
```

---

## Reference Documentation (Local)

Load these for detailed patterns:

- **[ingestion-patterns.md](ingestion-patterns.md)** - Auto Loader, Kafka, Event Hub, file formats
- **[streaming-patterns.md](streaming-patterns.md)** - Deduplication, windowing, stateful operations
- **[scd-query-patterns.md](scd-query-patterns.md)** - Querying SCD2 history tables
- **[python-api-versions.md](python-api-versions.md)** - Modern `dp` API vs legacy `dlt` API
- **[performance-tuning.md](performance-tuning.md)** - Liquid Clustering, optimization
- **[dlt-migration-guide.md](dlt-migration-guide.md)** - Migrating from DLT to SDP

---

## Best Practices (2025)

### Language Selection

Ask user if not specified:
- **SQL**: Simple transformations, SQL teams, declarative style
- **Python**: Complex logic, UDFs, Python teams (use modern `dp` API)

### Modern Defaults

- **Use `CLUSTER BY`** (Liquid Clustering), not `PARTITION BY`
- **Use raw `.sql`/`.py` files**, not notebooks
- **All pipelines are serverless** and use Unity Catalog
- **Use `read_files()`** for cloud storage ingestion

### File Structure

```
pipeline_name/
├── bronze/     # Raw ingestion
├── silver/     # Cleansed, validated
└── gold/       # Aggregated business layer
```

---

## Common Issues

| Issue | Solution |
|-------|----------|
| **Empty output tables** | Use `get_table_details` to verify, check upstream sources |
| **Pipeline stuck INITIALIZING** | Normal for serverless, wait a few minutes |
| **"Column not found"** | Check `schemaHints` match actual data |
| **Streaming reads fail** | Use `FROM STREAM(table)` for streaming sources |
| **Timeout during run** | Increase `timeout`, or use `wait_for_completion=False` and poll with `get_update` |
| **MV doesn't refresh** | Enable row tracking on source tables |
| **SCD2 schema errors** | Let SDP infer START_AT/END_AT columns |

**For detailed errors**, the `result["message"]` from `create_or_update_pipeline` includes suggested next steps. Use `get_pipeline_events(pipeline_id=...)` for full stack traces.

---

## Platform Constraints

| Constraint | Details |
|------------|---------|
| **Unity Catalog** | Required for all serverless pipelines |
| **CDC Features** | Requires serverless or Pro/Advanced edition |
| **Schema Evolution** | Streaming tables require full refresh for incompatible changes |
| **SQL Limitations** | PIVOT clause unsupported |
| **Sinks** | Python only, streaming only, append flows only |
