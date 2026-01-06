# Python API Versions: Modern vs Legacy

**Last Updated**: December 2025
**Status**: Modern API (`pyspark.pipelines`) is recommended for all new projects

---

## Overview

Databricks provides two Python APIs for building Spark Declarative Pipelines:

1. **Modern API** (`pyspark.pipelines` as `dp`) - **Recommended for new projects (2025)**
2. **Legacy API** (`dlt`) - Older Delta Live Tables API, still supported for existing code

**Key Recommendation**: Always use the **modern API** for new projects. Only use legacy API when maintaining existing DLT code.

---

## Quick Comparison

| Aspect | Modern API (`dp`) | Legacy API (`dlt`) |
|--------|-------------------|-------------------|
| **Import** | `from pyspark import pipelines as dp` | `import dlt` |
| **Status** | ✅ **Recommended (2025)** | ⚠️ Legacy |
| **Table decorator** | `@dp.table()` | `@dlt.table()` |
| **Read operation** | `dp.read.table("catalog.schema.table")` | `dlt.read("table")` |
| **Use for** | New projects | Maintaining existing DLT pipelines |
| **Documentation** | [Current Databricks LDP docs](https://docs.databricks.com/aws/en/ldp/) | [Legacy DLT docs](https://docs.databricks.com/aws/en/ldp/where-is-dlt) |

---

## Key Decision Questions

Before writing Python SDP code, clarify:

1. **Is this streaming or batch oriented?**
   - Streaming: Use Auto Loader, streaming tables
   - Batch: Use batch reads, materialized views

2. **Should the trigger be continuous?**
   - Yes: Real-time processing (sub-second latency)
   - No: Triggered execution (scheduled)

3. **Will it use serverless or classic compute?**
   - Serverless: Recommended for most workloads (auto-scaling, better price/performance)
   - Classic: When specific cluster configs required

---

## Side-by-Side Examples

### Basic Table Definition

**Modern API (Recommended)**:
```python
from pyspark import pipelines as dp
from pyspark.sql import functions as F

@dp.table(
    name="bronze_events",
    comment="Raw events from source system"
)
def bronze_events():
    """Ingest raw events using Auto Loader"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .load("/mnt/raw/events")
    )
```

**Legacy API**:
```python
import dlt
from pyspark.sql import functions as F

@dlt.table(
    name="bronze_events",
    comment="Raw events from source system"
)
def bronze_events():
    """Ingest raw events using Auto Loader"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .load("/mnt/raw/events")
    )
```

**Note**: Table definition is similar, but read operations differ significantly.

---

### Reading Tables

**Modern API (Recommended)**:
```python
@dp.table(name="silver_events")
def silver_events():
    # Explicit Unity Catalog three-part name
    return dp.read.table("catalog.schema.bronze_events").filter(...)
```

**Legacy API**:
```python
@dlt.table(name="silver_events")
def silver_events():
    # Implicit LIVE schema reference
    return dlt.read("bronze_events").filter(...)
```

**Key Difference**: Modern API uses explicit UC paths, legacy uses implicit `LIVE.*` schema.

---

### Streaming Reads

**Modern API (Recommended)**:
```python
@dp.table(name="silver_events")
def silver_events():
    # Read as stream (context-aware)
    return (
        dp.read.table("catalog.schema.bronze_events")
        .filter(F.col("event_type").isNotNull())
    )
```

**Legacy API**:
```python
@dlt.table(name="silver_events")
def silver_events():
    # Explicit streaming read
    return (
        dlt.read_stream("bronze_events")
        .filter(F.col("event_type").isNotNull())
    )
```

---

### Data Quality Expectations

**Modern API (Recommended)**:
```python
@dp.table(name="silver_validated")
@dp.expect_or_drop("valid_id", "id IS NOT NULL")
@dp.expect_or_drop("valid_amount", "amount > 0")
@dp.expect_or_fail("critical_field", "timestamp IS NOT NULL")
def silver_validated():
    return dp.read.table("catalog.schema.bronze_events")
```

**Legacy API**:
```python
@dlt.table(name="silver_validated")
@dlt.expect_or_drop("valid_id", "id IS NOT NULL")
@dlt.expect_or_drop("valid_amount", "amount > 0")
@dlt.expect_or_fail("critical_field", "timestamp IS NOT NULL")
def silver_validated():
    return dlt.read("bronze_events")
```

**Note**: Expectations API is identical between versions.

---

### SCD Type 2 with Apply Changes

**Modern API (Recommended)**:
```python
# Target table
dp.create_streaming_table("customers_history")

# Apply changes flow
dp.apply_changes(
    target="customers_history",
    source=dp.read.table("catalog.schema.customers_cdc"),
    keys=["customer_id"],
    sequence_by="event_timestamp",
    stored_as_scd_type="2",
    track_history_column_list=["*"]
)
```

**Legacy API**:
```python
# Target table
dlt.create_streaming_table("customers_history")

# Apply changes flow
dlt.apply_changes(
    target="customers_history",
    source="customers_cdc",
    keys=["customer_id"],
    sequence_by="event_timestamp",
    stored_as_scd_type="2",
    track_history_column_list=["*"]
)
```

---

### Table Properties and Liquid Clustering

**Modern API (Recommended)**:
```python
@dp.table(
    name="bronze_events",
    comment="Raw events with optimal clustering",
    table_properties={
        "delta.autoOptimize.optimizeWrite": "true",
        "delta.autoOptimize.autoCompact": "true"
    },
    cluster_by=["event_type", "event_date"]  # Liquid Clustering
)
def bronze_events():
    return spark.readStream.format("cloudFiles").load("/data")
```

**Legacy API**:
```python
@dlt.table(
    name="bronze_events",
    comment="Raw events with legacy partitioning",
    table_properties={
        "pipelines.autoOptimize.managed": "true",
        "pipelines.autoOptimize.zOrderCols": "event_type"
    },
    partition_cols=["event_date"]  # Legacy partitioning
)
def bronze_events():
    return spark.readStream.format("cloudFiles").load("/data")
```

**Key Difference**: Modern API supports `cluster_by` for Liquid Clustering; legacy uses `partition_cols`.

---

## Complete Medallion Example

### Modern API (Recommended)

```python
from pyspark import pipelines as dp
from pyspark.sql import functions as F

# Bronze: Raw ingestion
@dp.table(
    name="bronze_sales",
    comment="Raw sales data from source",
    cluster_by=["ingestion_date", "source_system"]
)
def bronze_sales():
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", "/checkpoints/bronze_sales")
        .load("/mnt/raw/sales/")
        .withColumn("ingestion_date", F.current_date())
        .withColumn("source_system", F.lit("crm"))
    )

# Silver: Cleansed and validated
@dp.table(
    name="silver_sales",
    comment="Cleansed sales data",
    cluster_by=["sale_date", "customer_id"]
)
@dp.expect_or_drop("valid_sale_id", "sale_id IS NOT NULL")
@dp.expect_or_drop("valid_amount", "amount > 0")
@dp.expect_or_fail("valid_date", "sale_date IS NOT NULL")
def silver_sales():
    return (
        dp.read.table("catalog.schema.bronze_sales")
        .withColumn("sale_date", F.to_date("sale_timestamp"))
        .withColumn("amount", F.col("amount").cast("decimal(10,2)"))
        .select("sale_id", "customer_id", "product_id", "amount", "sale_date")
    )

# Gold: Business aggregations
@dp.table(
    name="gold_daily_sales",
    comment="Daily sales summary",
    cluster_by=["sale_date"]
)
def gold_daily_sales():
    return (
        dp.read.table("catalog.schema.silver_sales")
        .groupBy("sale_date")
        .agg(
            F.count("*").alias("transaction_count"),
            F.sum("amount").alias("total_sales"),
            F.avg("amount").alias("avg_transaction_value")
        )
    )
```

### Legacy API

```python
import dlt
from pyspark.sql import functions as F

# Bronze: Raw ingestion
@dlt.table(
    name="bronze_sales",
    comment="Raw sales data from source",
    partition_cols=["ingestion_date"]
)
def bronze_sales():
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", "/checkpoints/bronze_sales")
        .load("/mnt/raw/sales/")
        .withColumn("ingestion_date", F.current_date())
        .withColumn("source_system", F.lit("crm"))
    )

# Silver: Cleansed and validated
@dlt.table(
    name="silver_sales",
    comment="Cleansed sales data",
    partition_cols=["sale_date"]
)
@dlt.expect_or_drop("valid_sale_id", "sale_id IS NOT NULL")
@dlt.expect_or_drop("valid_amount", "amount > 0")
@dlt.expect_or_fail("valid_date", "sale_date IS NOT NULL")
def silver_sales():
    return (
        dlt.read_stream("bronze_sales")
        .withColumn("sale_date", F.to_date("sale_timestamp"))
        .withColumn("amount", F.col("amount").cast("decimal(10,2)"))
        .select("sale_id", "customer_id", "product_id", "amount", "sale_date")
    )

# Gold: Business aggregations
@dlt.table(
    name="gold_daily_sales",
    comment="Daily sales summary"
)
def gold_daily_sales():
    return (
        dlt.read("silver_sales")
        .groupBy("sale_date")
        .agg(
            F.count("*").alias("transaction_count"),
            F.sum("amount").alias("total_sales"),
            F.avg("amount").alias("avg_transaction_value")
        )
    )
```

---

## Decision Matrix: Which API to Use?

### Use Modern API (`dp`) When:
- ✅ **Starting a new project** (default choice)
- ✅ **Learning SDP/LDP** (learn the current standard)
- ✅ **Want Liquid Clustering** support
- ✅ **Prefer explicit Unity Catalog paths**
- ✅ **Following 2025 best practices**

### Use Legacy API (`dlt`) When:
- ⚠️ **Maintaining existing DLT pipelines** (don't rewrite working code)
- ⚠️ **Team already trained on DLT** (consistency with existing codebase)
- ⚠️ **Using older DBR versions** (if modern API not available)

**Default Recommendation**: Use modern `dp` API unless you have a specific reason to use legacy.

---

## Migration Guide: dlt → dp

### Step 1: Update Imports

**Before**:
```python
import dlt
from pyspark.sql import functions as F
```

**After**:
```python
from pyspark import pipelines as dp
from pyspark.sql import functions as F
```

### Step 2: Update Table Decorators

**Before**:
```python
@dlt.table(name="my_table")
```

**After**:
```python
@dp.table(name="my_table")
```

### Step 3: Update Read Operations

**Before**:
```python
dlt.read("source_table")
dlt.read_stream("source_table")
```

**After**:
```python
dp.read.table("catalog.schema.source_table")
# Streaming is context-aware, no separate read_stream
```

### Step 4: Update Apply Changes

**Before**:
```python
dlt.apply_changes(target="dim_customer", source="cdc_source", ...)
```

**After**:
```python
dp.apply_changes(target="dim_customer", source=dp.read.table("catalog.schema.cdc_source"), ...)
```

### Step 5: Update Clustering/Partitioning

**Before**:
```python
@dlt.table(partition_cols=["date"])
```

**After**:
```python
@dp.table(cluster_by=["date", "other_col"])  # Liquid Clustering
```

---

## 2025 Best Practices

### 1. Use Liquid Clustering (Not PARTITION BY)

**Modern Approach**:
```python
@dp.table(cluster_by=["key_col", "date_col"])
def my_table():
    return ...

# Or automatic clustering
@dp.table(cluster_by=["AUTO"])
def my_table():
    return ...
```

**Reference**: [Databricks Liquid Clustering](https://docs.databricks.com/aws/en/delta/clustering)

### 2. Use forEachBatch for Advanced Sinks

For custom sinks beyond Delta tables:

```python
def write_to_custom_sink(batch_df, batch_id):
    # Custom write logic (e.g., external API, custom format)
    batch_df.write.format("custom").save(...)

@dp.table(name="my_table")
def my_table():
    return (
        spark.readStream
        .format("cloudFiles")
        .load("/data")
        .writeStream
        .foreachBatch(write_to_custom_sink)
    )
```

**Reference**: [forEachBatch Documentation](https://docs.databricks.com/aws/en/ldp/for-each-batch)

### 3. Optimize Materialized Views

For gold layer aggregations:

```python
@dp.table(
    name="gold_sales_summary",
    table_properties={
        "delta.autoOptimize.optimizeWrite": "true"
    },
    cluster_by=["year_month", "category"]
)
def gold_sales_summary():
    return (
        dp.read.table("catalog.schema.silver_sales")
        .groupBy(...)
        .agg(...)
    )
```

**Reference**: [Materialized View Optimization](https://www.databricks.com/blog/optimizing-materialized-views-recomputes)

---

## Documentation Links

### Modern API (`dp`)
- [Lakeflow Declarative Pipelines Overview](https://docs.databricks.com/aws/en/ldp/)
- [Where is DLT? (Migration Guide)](https://docs.databricks.com/aws/en/ldp/where-is-dlt)
- [Liquid Clustering](https://docs.databricks.com/aws/en/delta/clustering)

### Newer features
- [forEachBatch](https://docs.databricks.com/aws/en/ldp/for-each-batch)

### Legacy API (`dlt`)
- [Delta Live Tables Legacy Docs](https://docs.databricks.com/delta-live-tables/)
- Historical documentation for maintaining existing pipelines

---

## Summary

**For New Projects**: Use modern `pyspark.pipelines` (`dp`) API
- ✅ Current best practice (2025)
- ✅ Liquid Clustering support
- ✅ Explicit Unity Catalog paths
- ✅ Better alignment with Databricks platform evolution

**For Existing Projects**: Legacy `dlt` API remains fully supported
- ⚠️ Migrate when convenient, not urgent
- ⚠️ Consider modern API for new files in existing projects

**Key Takeaway**: Modern API provides same functionality as legacy, plus new features. Start all new projects with `from pyspark import pipelines as dp`.
