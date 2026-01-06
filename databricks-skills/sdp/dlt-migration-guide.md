# DLT to SDP Migration Guide

## Overview

This guide helps migrate existing Delta Live Tables (DLT) Python pipelines to Lakeflow Spark Declarative Pipelines (SDP) using SQL.

---

## ⚠️ IMPORTANT: Python API Version Notice

**If you're creating NEW Python SDP pipelines** (not migrating to SQL), use the **modern API**:

```python
from pyspark import pipelines as dp  # ✅ Modern (recommended for new projects)
```

**NOT the legacy API shown in this guide**:
```python
import dlt  # ⚠️ Legacy (only for maintaining existing DLT code)
```

This guide shows legacy `dlt` API **only for migration context**. For new Python SDP projects, see **[python-api-versions.md](python-api-versions.md)** for modern API guidance.

---

## Migration Decision Matrix

Use this matrix to determine if migration to SDP SQL is appropriate:

| Feature/Pattern | DLT Python | SDP SQL | Recommendation |
|-----------------|------------|---------|----------------|
| **Simple transformations** | ✓ | ✓ | Migrate to SQL |
| **Aggregations** | ✓ | ✓ | Migrate to SQL |
| **Filtering and WHERE clauses** | ✓ | ✓ | Migrate to SQL |
| **CASE expressions** | ✓ | ✓ | Migrate to SQL |
| **SCD Type 1/2** | ✓ | ✓ | Migrate to SQL (AUTO CDC) |
| **Simple joins** | ✓ | ✓ | Migrate to SQL |
| **Auto Loader from cloud** | ✓ | ✓ | Migrate to SQL (read_files) |
| **Streaming sources (Kafka)** | ✓ | ✓ | Migrate to SQL (read_stream) |
| **Complex Python UDFs** | ✓ | ❌ | Stay in Python or rewrite as SQL |
| **External API calls** | ✓ | ❌ | Stay in Python |
| **Custom libraries** | ✓ | ❌ | Stay in Python |
| **Complex apply functions** | ✓ | ❌ | Stay in Python or simplify |
| **ML model inference** | ✓ | ❌ | Stay in Python |

**Rule of Thumb**: If your pipeline is 80%+ SQL-expressible transformations, migrate to SDP SQL. If heavily dependent on Python logic, stay with DLT Python or use hybrid approach.

---

## Side-by-Side: DLT Python vs SDP SQL

### Basic Streaming Table

**DLT Python**:
```python
@dlt.table(
    name="bronze_sales",
    comment="Raw sales data"
)
def bronze_sales():
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .load("/mnt/raw/sales")
        .withColumn("_ingested_at", F.current_timestamp())
    )
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE bronze_sales
COMMENT 'Raw sales data'
AS
SELECT
  *,
  current_timestamp() AS _ingested_at
FROM read_files(
  '/mnt/raw/sales',
  format => 'json'
);
```

---

### Filtering and Transformations

**DLT Python**:
```python
@dlt.table(name="silver_sales")
@dlt.expect_or_drop("valid_amount", "amount > 0")
@dlt.expect_or_drop("valid_sale_id", "sale_id IS NOT NULL")
def silver_sales():
    return (
        dlt.read_stream("bronze_sales")
        .withColumn("sale_date", F.to_date("sale_date"))
        .withColumn("amount", F.col("amount").cast("decimal(10,2)"))
        .select("sale_id", "customer_id", "amount", "sale_date")
    )
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE silver_sales AS
SELECT
  sale_id,
  customer_id,
  CAST(amount AS DECIMAL(10,2)) AS amount,
  CAST(sale_date AS DATE) AS sale_date
FROM STREAM bronze_sales
WHERE amount > 0
  AND sale_id IS NOT NULL;
```

**Note**: SDP SQL uses WHERE clauses for filtering. For more advanced data quality, consider adding quarantine patterns (see below).

---

### Aggregations

**DLT Python**:
```python
@dlt.table(name="gold_daily_sales")
def gold_daily_sales():
    return (
        dlt.read("silver_sales")
        .groupBy(F.to_date("sale_date").alias("sale_day"))
        .agg(
            F.count("*").alias("transaction_count"),
            F.sum("amount").alias("total_sales")
        )
    )
```

**SDP SQL**:
```sql
CREATE OR REPLACE MATERIALIZED VIEW gold_daily_sales AS
SELECT
  CAST(sale_date AS DATE) AS sale_day,
  COUNT(*) AS transaction_count,
  SUM(amount) AS total_sales
FROM silver_sales
GROUP BY CAST(sale_date AS DATE);
```

---

### SCD Type 2

**DLT Python**:
```python
import dlt

dlt.create_streaming_table("customers_history")

dlt.apply_changes(
    target="customers_history",
    source="customers_cdc_clean",
    keys=["customer_id"],
    sequence_by="event_timestamp",
    stored_as_scd_type="2",
    track_history_column_list=["*"]
)
```

**SDP SQL**:
```sql
-- Target table
CREATE OR REFRESH STREAMING TABLE customers_history;

-- AUTO CDC flow
CREATE FLOW customers_scd2_flow AS
AUTO CDC INTO customers_history
FROM stream(customers_cdc_clean)
KEYS (customer_id)
SEQUENCE BY event_timestamp
COLUMNS * EXCEPT (_rescued_data)
STORED AS SCD TYPE 2
TRACK HISTORY ON *;
```

---

### Joins

**DLT Python**:
```python
@dlt.table(name="silver_sales_enriched")
def silver_sales_enriched():
    sales = dlt.read_stream("silver_sales")
    products = dlt.read("dim_products")

    return (
        sales.join(products, "product_id", "left")
        .select(sales["*"], products["product_name"], products["category"])
    )
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE silver_sales_enriched AS
SELECT
  s.*,
  p.product_name,
  p.category
FROM STREAM silver_sales s
LEFT JOIN dim_products p
  ON s.product_id = p.product_id;
```

---

## Handling Expectations and Data Quality

### DLT Expectations

**DLT Python**:
```python
@dlt.expect_or_drop("valid_amount", "amount > 0")       # Drop invalid rows
@dlt.expect_or_fail("critical_id", "id IS NOT NULL")   # Fail pipeline on violation
@dlt.expect("warn_only", "date >= '2020-01-01'")       # Warn but continue
```

**SDP SQL - Basic Approach**:
```sql
-- Use WHERE clauses for filtering (equivalent to expect_or_drop)
CREATE OR REPLACE STREAMING TABLE silver_data AS
SELECT *
FROM STREAM bronze_data
WHERE amount > 0        -- expect_or_drop equivalent
  AND id IS NOT NULL;   -- expect_or_drop equivalent
```

**SDP SQL - Quarantine Pattern** (for auditing dropped records):
```sql
-- Flag invalid records
CREATE OR REPLACE STREAMING TABLE bronze_data_flagged AS
SELECT
  *,
  CASE
    WHEN amount <= 0 THEN TRUE
    WHEN id IS NULL THEN TRUE
    ELSE FALSE
  END AS is_invalid
FROM STREAM bronze_data;

-- Clean data for downstream
CREATE OR REPLACE STREAMING TABLE silver_data_clean AS
SELECT * FROM STREAM bronze_data_flagged WHERE NOT is_invalid;

-- Quarantine for investigation
CREATE OR REPLACE STREAMING TABLE silver_data_quarantine AS
SELECT * FROM STREAM bronze_data_flagged WHERE is_invalid;
```

**Migration Strategy**:
- `@dlt.expect_or_drop` → Use WHERE clause or quarantine pattern
- `@dlt.expect_or_fail` → Use WHERE clause (pipeline fails if filter removes all data)
- `@dlt.expect` (warn) → Consider monitoring quarantine tables instead

---

## Handling Python UDFs

### Simple UDFs (Migrate to SQL)

**DLT Python**:
```python
@F.udf(returnType=StringType())
def categorize_amount(amount):
    if amount > 1000:
        return "High"
    elif amount > 100:
        return "Medium"
    else:
        return "Low"

@dlt.table(name="sales_categorized")
def sales_categorized():
    return (
        dlt.read("sales")
        .withColumn("category", categorize_amount(F.col("amount")))
    )
```

**SDP SQL** (use CASE expression):
```sql
CREATE OR REPLACE MATERIALIZED VIEW sales_categorized AS
SELECT
  *,
  CASE
    WHEN amount > 1000 THEN 'High'
    WHEN amount > 100 THEN 'Medium'
    ELSE 'Low'
  END AS category
FROM sales;
```

### Complex UDFs (Stay in Python)

For complex logic that cannot be expressed in SQL:

**Option 1**: Keep the transformation in Python DLT pipeline
**Option 2**: Create a hybrid pipeline (SQL for most, Python for specific UDFs)
**Option 3**: Refactor if possible to use SQL built-in functions

```python
# Complex UDF that should stay in Python
@F.udf(returnType=StringType())
def complex_business_logic(data, external_api_response):
    # Complex conditional logic
    # External API calls
    # Custom algorithms
    return result

# This cannot be easily migrated to SQL
```

---

## Table Properties Migration

**DLT Python**:
```python
@dlt.table(
    name="bronze_data",
    table_properties={
        "quality": "bronze",
        "pipelines.autoOptimize.managed": "true",
        "delta.enableChangeDataFeed": "true"
    }
)
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE bronze_data
TBLPROPERTIES (
  'quality' = 'bronze',
  'pipelines.autoOptimize.managed' = 'true',
  'delta.enableChangeDataFeed' = 'true'
)
AS
SELECT * FROM ...;
```

---

## Comments and Metadata

**DLT Python**:
```python
@dlt.table(
    name="customer_sales",
    comment="Customer sales aggregated by month"
)
```

**SDP SQL**:
```sql
CREATE OR REPLACE MATERIALIZED VIEW customer_sales
COMMENT 'Customer sales aggregated by month'
AS
SELECT ...;
```

---

## Common Migration Patterns

### Pattern 1: Chain of Transformations

**DLT Python**:
```python
@dlt.table(name="bronze")
def bronze():
    return spark.readStream.load(...)

@dlt.table(name="silver")
def silver():
    return dlt.read_stream("bronze").filter(...).select(...)

@dlt.table(name="gold")
def gold():
    return dlt.read("silver").groupBy(...).agg(...)
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE bronze AS
SELECT * FROM read_files(...);

CREATE OR REPLACE STREAMING TABLE silver AS
SELECT ... FROM STREAM bronze WHERE ...;

CREATE OR REPLACE MATERIALIZED VIEW gold AS
SELECT ... FROM silver GROUP BY ...;
```

### Pattern 2: Multiple Sources Joining

**DLT Python**:
```python
@dlt.table(name="enriched")
def enriched():
    source1 = dlt.read_stream("bronze_source1")
    source2 = dlt.read_stream("bronze_source2")
    return source1.join(source2, "key")
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE enriched AS
SELECT
  s1.*,
  s2.additional_field
FROM STREAM bronze_source1 s1
INNER JOIN STREAM bronze_source2 s2
  ON s1.key = s2.key;
```

### Pattern 3: Static Reference Data Join

**DLT Python**:
```python
@dlt.table(name="enriched")
def enriched():
    streaming_data = dlt.read_stream("bronze_stream")
    static_data = dlt.read("dim_reference")
    return streaming_data.join(static_data, "key")
```

**SDP SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE enriched AS
SELECT
  s.*,
  r.reference_field
FROM STREAM bronze_stream s
LEFT JOIN dim_reference r
  ON s.key = r.key;
```

---

## Step-by-Step Migration Process

### Step 1: Inventory Current Pipeline

Document:
- Number of tables/views
- Use of Python UDFs (complex vs simple)
- External dependencies (APIs, libraries)
- Expectations and data quality rules
- Auto Loader configurations

### Step 2: Categorize Transformations

Group into:
- **Easy to migrate**: Filters, aggregations, simple CASE expressions
- **Moderate**: UDFs that can be rewritten as SQL
- **Hard**: Complex Python logic, external calls, ML inference

### Step 3: Create Migration Plan

Migrate in phases:
1. Bronze layer (ingestion)
2. Silver layer (cleansing, joins)
3. Gold layer (aggregations)
4. SCD/CDC flows

### Step 4: Migrate Bronze Layer

Focus on:
- Converting Auto Loader to read_files()
- Preserving file format options
- Adding metadata columns

### Step 5: Migrate Silver Layer

Focus on:
- Converting expectations to WHERE clauses or quarantine patterns
- Rewriting simple UDFs as CASE expressions
- Preserving join logic

### Step 6: Migrate Gold Layer

Usually straightforward:
- Aggregations translate directly
- Use MATERIALIZED VIEW for static aggregations

### Step 7: Test and Validate

- Run both pipelines in parallel
- Compare outputs for correctness
- Validate performance
- Check data quality metrics

---

## When NOT to Migrate

Stay with DLT Python if:

1. **Heavy Python UDF usage** (>30% of logic)
2. **External API calls** required in transformations
3. **Custom ML model inference** in pipeline
4. **Complex stateful operations** not expressible in SQL
5. **Existing pipeline works well** and team prefers Python
6. **Limited SQL expertise** on team

Consider hybrid: Use SDP SQL for most transformations, keep Python for specific complex logic.

---

## Hybrid Approach (SQL + Python)

For pipelines with both simple transformations and complex Python logic:

1. **Separate concerns**: SQL for data movement and simple transforms, Python for complex logic
2. **Interface through tables**: SQL writes to tables, Python reads from those tables
3. **Organize by capability**: Use each tool for what it does best

---

## Troubleshooting Migration Issues

### Issue: UDF doesn't translate to SQL
**Solution**: Keep in Python or refactor using SQL built-in functions

### Issue: Expectations behave differently
**Solution**: Use quarantine pattern to audit dropped records

### Issue: Performance degradation after migration
**Solution**: Use CLUSTER BY for Liquid Clustering, review join strategies

### Issue: Schema evolution handled differently
**Solution**: Use `mode => 'PERMISSIVE'` in read_files() for Auto Loader

---

## Migration Checklist

- [ ] Inventory all tables and transformations
- [ ] Identify Python UDFs and assess SQL feasibility
- [ ] Document expectations and data quality rules
- [ ] Create new SDP SQL pipeline in parallel
- [ ] Migrate bronze layer and validate
- [ ] Migrate silver layer and validate
- [ ] Migrate gold layer and validate
- [ ] Migrate SCD/CDC flows
- [ ] Test with production data
- [ ] Compare outputs between DLT Python and SDP SQL
- [ ] Performance test
- [ ] Document any remaining Python dependencies
- [ ] Train team on SQL pipeline
- [ ] Cutover to SDP SQL pipeline
