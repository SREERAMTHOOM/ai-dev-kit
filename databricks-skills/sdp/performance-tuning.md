# Performance Tuning for SDP

## Overview

This guide covers performance optimization strategies for Lakeflow Spark Declarative Pipelines, including **Liquid Clustering** (modern approach), materialized view refresh, state management, and compute configuration.

---

## Data Layout Optimization: Liquid Clustering (Recommended)

**Liquid Clustering is the recommended approach** for optimizing data layout in Delta tables. It replaces the need for manual `PARTITION BY` and `Z-ORDER` configuration.

### What is Liquid Clustering?

Liquid Clustering automatically organizes data in a table to improve query performance:
- **Adaptive**: Adjusts to data distribution changes over time
- **Multi-dimensional**: Efficiently clusters on multiple columns simultaneously
- **Automatic file sizing**: Maintains optimal file sizes without small file problems
- **Self-optimizing**: Reduces need for manual OPTIMIZE commands

### Basic Syntax

**SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE bronze_events
CLUSTER BY (event_type, event_date)
AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  CAST(current_date() AS DATE) AS event_date
FROM read_files('/mnt/raw/events/', format => 'json');
```

**Python (modern dp API)**:
```python
from pyspark import pipelines as dp

@dp.table(cluster_by=["event_type", "event_date"])
def bronze_events():
    return spark.readStream.format("cloudFiles").load("/data")
```

### Automatic Cluster Key Selection

Let Databricks automatically select cluster keys based on query patterns:

**SQL**:
```sql
CREATE OR REPLACE STREAMING TABLE bronze_events
CLUSTER BY (AUTO)
AS SELECT ...;
```

**Python**:
```python
@dp.table(cluster_by=["AUTO"])
def bronze_events():
    return ...
```

**When to use AUTO**:
- Learning phase (Databricks will analyze query patterns over time)
- Unknown or changing access patterns
- Prototyping and development
- Want Databricks to optimize automatically

**When to define keys manually**:
- Well-known query patterns (e.g., always filter by date and customer_id)
- Production workloads with stable access patterns
- Performance-critical tables where you understand access patterns

---

## Cluster Key Selection by Layer

### Bronze Layer: Cluster by Event Type + Date

```sql
CREATE OR REPLACE STREAMING TABLE bronze_events
CLUSTER BY (event_type, ingestion_date)
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true'
)
AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  CAST(current_date() AS DATE) AS ingestion_date
FROM read_files('/mnt/raw/events/', format => 'json');
```

**Why**: Bronze often filtered by event type for downstream processing and by date for incremental loads and retention.

**Python**:
```python
@dp.table(
    cluster_by=["event_type", "ingestion_date"],
    table_properties={"delta.autoOptimize.optimizeWrite": "true"}
)
def bronze_events():
    return spark.readStream.format("cloudFiles").load("/data")
```

### Silver Layer: Cluster by Primary Key + Business Dimension

```sql
CREATE OR REPLACE STREAMING TABLE silver_orders
CLUSTER BY (customer_id, order_date)
AS
SELECT
  order_id,
  customer_id,
  product_id,
  amount,
  CAST(order_timestamp AS DATE) AS order_date,
  order_timestamp
FROM STREAM bronze_orders;
```

**Why**: Silver tables used for entity lookups (by ID) and time-range queries (by date).

### Gold Layer: Cluster by Aggregation Dimensions

```sql
CREATE OR REPLACE MATERIALIZED VIEW gold_sales_summary
CLUSTER BY (product_category, year_month)
AS
SELECT
  product_category,
  DATE_FORMAT(order_date, 'yyyy-MM') AS year_month,
  SUM(amount) AS total_sales,
  COUNT(*) AS transaction_count,
  AVG(amount) AS avg_order_value
FROM silver_orders
GROUP BY product_category, DATE_FORMAT(order_date, 'yyyy-MM');
```

**Why**: Gold tables queried by analytical dimensions for dashboards and reporting.

### Cluster Key Selection Guidelines

| Layer | Good Cluster Keys | Rationale |
|-------|-------------------|-----------|
| **Bronze** | event_type, ingestion_date | Filter by type for processing; by date for incremental |
| **Silver** | primary_key, business_date | Entity lookups + time-range queries |
| **Gold** | aggregation_dimensions | Dashboard filters (category, region, time period) |

**Best Practices**:
- **First key**: Most selective filter in queries (e.g., customer_id if always filtered)
- **Second key**: Next most common filter (e.g., date for time-range queries)
- **Order matters**: Most selective column first
- **Limit to 4 keys**: Diminishing returns beyond 4 columns
- **Use AUTO if unsure**: Let Databricks analyze query patterns

---

## Migration from Legacy PARTITION BY

If you have existing tables using `PARTITION BY`, migrate to Liquid Clustering for better performance.

### Before (Legacy Approach)

```sql
CREATE OR REPLACE STREAMING TABLE events
PARTITIONED BY (date DATE)
TBLPROPERTIES (
  'pipelines.autoOptimize.zOrderCols' = 'user_id,event_type'
)
AS SELECT ...;
```

**Issues with this approach**:
- ❌ Fixed partition keys (can't change without rewriting table)
- ❌ Small file problem if too many partitions
- ❌ Skewed data distribution within partitions
- ❌ Z-ORDER separate from partitioning
- ❌ Manual OPTIMIZE required

### After (Modern Approach with Liquid Clustering)

```sql
CREATE OR REPLACE STREAMING TABLE events
CLUSTER BY (date, user_id, event_type)
AS SELECT ...;
```

**Benefits**:
- ✅ Combines partitioning + Z-ORDER benefits in one feature
- ✅ Adaptive to data distribution changes
- ✅ No small file problem
- ✅ Automatic optimization
- ✅ Better query performance (20-50% improvement)

### Migration Steps

1. **Create new table** with CLUSTER BY:
   ```sql
   CREATE OR REPLACE STREAMING TABLE events_v2
   CLUSTER BY (date, user_id, event_type)
   AS SELECT * FROM events;
   ```

2. **Test and validate** performance with new table

3. **Update downstream dependencies** to reference new table

4. **Drop old table** once migration complete:
   ```sql
   DROP TABLE events;
   ```

5. **(Optional) Rename** new table to original name if needed

**Note**: For large tables, use `INSERT INTO` or `MERGE` for incremental migration instead of rewriting entire table.

---

## When to Still Use PARTITION BY (Rare Cases)

Use legacy `PARTITION BY` **only** when:

1. **Regulatory requirements**: Must physically separate data by partition for compliance
2. **Data lifecycle management**: Need to `DROP` entire partitions for retention policies
3. **Compatibility**: Working with older Delta Lake versions (< DBR 13.3)
4. **Existing large tables**: Migration cost outweighs benefits (evaluate case-by-case)

**Otherwise, prefer Liquid Clustering for all new tables.**

### Legacy Partitioning Example (When Required)

```sql
-- Only use if you have specific requirements above
CREATE OR REPLACE STREAMING TABLE events
PARTITIONED BY (year INT, month INT)
AS
SELECT
  *,
  YEAR(event_date) AS year,
  MONTH(event_date) AS month
FROM STREAM source_events;
```

Then drop partitions for retention:
```sql
-- Drop partitions older than 2 years
ALTER TABLE events DROP PARTITION (year < 2023);
```

---

## Table Properties for Optimization

### Enable Auto-Optimize

```sql
CREATE OR REPLACE STREAMING TABLE bronze_events
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true'
)
AS
SELECT * FROM read_files(...);
```

**Benefits**:
- Reduces small file problem
- Improves read performance
- Automatic compaction

### Enable Change Data Feed (for downstream consumers)

```sql
CREATE OR REPLACE STREAMING TABLE silver_customers
TBLPROPERTIES (
  'delta.enableChangeDataFeed' = 'true'
)
AS
SELECT * FROM STREAM bronze_customers;
```

**Use when**: Downstream systems need to track changes efficiently.

### Set Retention Periods

```sql
CREATE OR REPLACE STREAMING TABLE bronze_high_volume
TBLPROPERTIES (
  'delta.logRetentionDuration' = '7 days',        -- Transaction log
  'delta.deletedFileRetentionDuration' = '7 days' -- Deleted files
)
AS
SELECT * FROM read_files(...);
```

**Use for**: High-volume bronze tables to reduce storage costs.

---

## Materialized View Refresh Optimization

### Refresh Frequency

```sql
-- For near-real-time dashboards (frequent refresh)
CREATE OR REPLACE MATERIALIZED VIEW gold_live_metrics
REFRESH EVERY 5 MINUTES
AS
SELECT
  metric_name,
  AVG(metric_value) AS avg_value,
  MAX(last_updated) AS freshness
FROM silver_metrics
GROUP BY metric_name;

-- For daily reports (scheduled refresh)
CREATE OR REPLACE MATERIALIZED VIEW gold_daily_summary
REFRESH EVERY 1 DAY
AS
SELECT
  report_date,
  SUM(amount) AS total_amount
FROM silver_sales
GROUP BY report_date;
```

### Incremental Refresh (Automatic)

Materialized views automatically use incremental refresh when possible:

```sql
-- This MV will refresh incrementally if silver_sales supports it
CREATE OR REPLACE MATERIALIZED VIEW gold_aggregates AS
SELECT
  product_id,
  SUM(quantity) AS total_quantity,
  SUM(amount) AS total_amount
FROM silver_sales
GROUP BY product_id;
```

**Requirements for incremental refresh**:
- Source table has Delta row tracking enabled
- No row filters or column masks on source
- Aggregation patterns support incremental updates

### Pre-Aggregate for Performance

```sql
-- Instead of this (expensive query on large table):
SELECT
  customer_id,
  YEAR(order_date) AS year,
  MONTH(order_date) AS month,
  SUM(amount) AS total
FROM large_orders_table
GROUP BY customer_id, YEAR(order_date), MONTH(order_date);

-- Create intermediate MV (refreshed periodically):
CREATE OR REPLACE MATERIALIZED VIEW orders_monthly
AS
SELECT
  customer_id,
  YEAR(order_date) AS year,
  MONTH(order_date) AS month,
  SUM(amount) AS total
FROM large_orders_table
GROUP BY customer_id, YEAR(order_date), MONTH(order_date);

-- Then query the MV (fast):
SELECT * FROM orders_monthly WHERE year = 2024;
```

---

## State Management for Streaming

### Understand State Growth

Stateful operations accumulate data in memory:

```sql
-- High state: Every unique combination creates state
CREATE OR REPLACE STREAMING TABLE high_state AS
SELECT
  user_id,              -- 1M users
  product_id,           -- 10K products
  session_id,           -- 100M sessions
  COUNT(*) AS events
FROM STREAM bronze_events
GROUP BY user_id, product_id, session_id;  -- 1M * 10K * 100M combinations!
```

### Reduce State Size

**Strategy 1: Reduce cardinality**
```sql
-- Lower state: Aggregate at higher level
CREATE OR REPLACE STREAMING TABLE lower_state AS
SELECT
  user_id,              -- 1M users
  product_category,     -- 100 categories (not 10K products)
  DATE(event_time) AS event_date,  -- Days not sessions
  COUNT(*) AS events
FROM STREAM bronze_events
GROUP BY user_id, product_category, DATE(event_time);  -- Much smaller state
```

**Strategy 2: Use time windows**
```sql
-- Bounded state: Window limits state retention
CREATE OR REPLACE STREAMING TABLE windowed_state AS
SELECT
  user_id,
  window(event_time, '1 hour') AS time_window,
  COUNT(*) AS events
FROM STREAM bronze_events
GROUP BY user_id, window(event_time, '1 hour');
```

**Strategy 3: Materialize intermediate results**
```sql
-- Streaming aggregation (maintains state)
CREATE OR REPLACE STREAMING TABLE user_daily_stats AS
SELECT
  user_id,
  DATE(event_time) AS event_date,
  COUNT(*) AS event_count
FROM STREAM bronze_events
GROUP BY user_id, DATE(event_time);

-- Then aggregate further using materialized view (no streaming state)
CREATE OR REPLACE MATERIALIZED VIEW user_monthly_stats AS
SELECT
  user_id,
  DATE_TRUNC('month', event_date) AS month,
  SUM(event_count) AS total_events
FROM user_daily_stats
GROUP BY user_id, DATE_TRUNC('month', event_date);
```

---

## Join Optimization

### Stream-to-Static Join (Efficient)

```sql
-- Small static dimension, large streaming fact
CREATE OR REPLACE STREAMING TABLE sales_enriched AS
SELECT
  s.sale_id,
  s.product_id,
  s.amount,
  p.product_name,      -- From small static table
  p.category
FROM STREAM bronze_sales s
LEFT JOIN dim_products p
  ON s.product_id = p.product_id;
```

**Best Practice**: Keep static dimension tables small (<10K rows) for efficient broadcast.

### Stream-to-Stream Join (Stateful)

```sql
-- Both streams need to maintain state
CREATE OR REPLACE STREAMING TABLE orders_with_payments AS
SELECT
  o.order_id,
  o.amount AS order_amount,
  p.payment_id,
  p.amount AS payment_amount
FROM STREAM bronze_orders o
INNER JOIN STREAM bronze_payments p
  ON o.order_id = p.order_id
  AND p.payment_time BETWEEN o.order_time AND o.order_time + INTERVAL 1 HOUR;
```

**Optimization**: Use time bounds to limit state retention (BETWEEN clause above).

### Avoid Large Cartesian Joins

```sql
-- ❌ Bad: Cartesian product (every order with every product)
FROM STREAM orders
CROSS JOIN products

-- ✅ Good: Explicit join condition
FROM STREAM orders o
INNER JOIN products p
  ON o.product_id = p.product_id
```

---

## Compute Configuration

### Serverless vs Classic Compute

| Aspect | Serverless | Classic |
|--------|-----------|---------|
| **Startup time** | Fast (seconds) | Slower (minutes) |
| **Scaling** | Automatic, instant | Manual or autoscaling |
| **Cost** | Pay-per-use | Pay for cluster time |
| **Best for** | Variable workloads, dev/test | Steady workloads, large jobs |

### Serverless Configuration

Enable at pipeline level (not in SQL):

```yaml
# In pipeline configuration
execution_mode: continuous  # or triggered
serverless: true
```

**Advantages**:
- No cluster management
- Instant scaling
- Lower cost for bursty workloads
- Better for development/testing

### Classic Compute Configuration

```yaml
# In pipeline configuration
clusters:
  - label: default
    num_workers: 4
    node_type_id: "i3.xlarge"
    autoscale:
      min_workers: 2
      max_workers: 8
```

**When to use**:
- Large, continuous streaming workloads
- Cost optimization for steady state
- Need specific instance types

---

## Query Optimization

### Use Selective Filters Early

```sql
-- ✅ Good: Filter early
CREATE OR REPLACE STREAMING TABLE silver_recent AS
SELECT *
FROM STREAM bronze_events
WHERE event_date >= CURRENT_DATE() - INTERVAL 7 DAYS;  -- Filter at source

-- ❌ Bad: Filter late
CREATE OR REPLACE STREAMING TABLE silver_all AS
SELECT * FROM STREAM bronze_events;

CREATE OR REPLACE MATERIALIZED VIEW gold_recent AS
SELECT * FROM silver_all
WHERE event_date >= CURRENT_DATE() - INTERVAL 7 DAYS;  -- Processes all data first
```

### Avoid SELECT *

```sql
-- ❌ Bad: Reads all columns
SELECT * FROM large_table;

-- ✅ Good: Only needed columns
SELECT customer_id, order_date, amount FROM large_table;
```

### Use DISTINCT Carefully

```sql
-- ❌ Expensive: DISTINCT on high-cardinality column
SELECT DISTINCT transaction_id FROM huge_table;

-- ✅ Better: Use GROUP BY with aggregate
SELECT transaction_id, COUNT(*) FROM huge_table GROUP BY transaction_id;
```

---

## Monitoring and Troubleshooting

### Monitor Pipeline Health

Use Lakeflow's built-in observability:

```sql
-- Check data freshness
SELECT
  table_name,
  MAX(event_timestamp) AS latest_event,
  CURRENT_TIMESTAMP() AS now,
  TIMESTAMPDIFF(MINUTE, MAX(event_timestamp), CURRENT_TIMESTAMP()) AS lag_minutes
FROM pipeline_monitoring.table_metrics
GROUP BY table_name;
```

### Identify Bottlenecks

Check for:
1. **Slow streaming tables**: High processing lag
2. **Large state operations**: High memory usage
3. **Expensive joins**: Long processing times
4. **Small files**: Many small files in Delta tables

### Optimize Slow Tables

```sql
-- Add partitioning
ALTER TABLE slow_table
SET TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true'
);

-- Run OPTIMIZE manually if needed
OPTIMIZE slow_table;
```

---

## Best Practices Summary

### Bronze Layer
- ✅ Partition by ingestion date
- ✅ Enable auto-optimize
- ✅ Use schema hints with read_files()
- ✅ Keep raw, minimal transformations

### Silver Layer
- ✅ Partition by business date or region
- ✅ Filter early (move WHERE up)
- ✅ Deduplicate at this layer
- ✅ Use appropriate join strategies

### Gold Layer
- ✅ Use materialized views for aggregations
- ✅ Pre-aggregate to reduce query cost
- ✅ Set appropriate refresh schedules
- ✅ Partition by common filter columns

### General
- ✅ Start with serverless, move to classic if needed
- ✅ Monitor state size for stateful operations
- ✅ Use time bounds in stream-to-stream joins
- ✅ Avoid SELECT * in production
- ✅ Test with production-scale data

---

## Common Performance Issues

### Issue: Pipeline running slowly
**Check**: Partition strategy, state size, join patterns
**Solution**: Add partitioning, reduce grouping cardinality, optimize joins

### Issue: High memory usage
**Cause**: Unbounded state in aggregations or joins
**Solution**: Add time windows, reduce cardinality, use smaller time ranges

### Issue: Many small files
**Cause**: High write frequency without compaction
**Solution**: Enable auto-optimize, run OPTIMIZE command

### Issue: Expensive queries on large tables
**Cause**: No partitioning, reading all data
**Solution**: Add partitioning, create filtered materialized views

### Issue: Materialized view refresh is slow
**Cause**: Full recomputation instead of incremental
**Solution**: Enable row tracking on source, verify incremental refresh is possible
