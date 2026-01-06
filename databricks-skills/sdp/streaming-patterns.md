# Streaming Patterns for SDP

## Overview

This guide covers streaming-specific patterns including deduplication, windowed aggregations, late-arriving data handling, and stateful operations.

---

## Deduplication Patterns

### Simple Deduplication by Key

```sql
-- Bronze: Ingest all events (may contain duplicates)
CREATE OR REPLACE STREAMING TABLE bronze_events AS
SELECT
  *,
  current_timestamp() AS _ingested_at
FROM read_stream(...);

-- Silver: Deduplicate by event_id, keeping first occurrence
CREATE OR REPLACE STREAMING TABLE silver_events_dedup AS
SELECT
  event_id,
  user_id,
  event_type,
  event_timestamp,
  _ingested_at
FROM (
  SELECT
    *,
    ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY event_timestamp) AS rn
  FROM STREAM bronze_events
)
WHERE rn = 1;
```

### Deduplication with Time Window

Deduplicate events within a time window to handle late arrivals:

```sql
CREATE OR REPLACE STREAMING TABLE silver_events_dedup AS
SELECT
  event_id,
  user_id,
  event_type,
  event_timestamp,
  MIN(_ingested_at) AS first_seen_at
FROM STREAM bronze_events
GROUP BY
  event_id,
  user_id,
  event_type,
  event_timestamp,
  window(event_timestamp, '1 hour')  -- Deduplicate within 1-hour windows
HAVING COUNT(*) >= 1
SELECT
  event_id,
  user_id,
  event_type,
  event_timestamp,
  first_seen_at;
```

### Composite Key Deduplication

```sql
-- Deduplicate by combination of fields
CREATE OR REPLACE STREAMING TABLE silver_transactions_dedup AS
SELECT
  transaction_id,
  customer_id,
  amount,
  transaction_timestamp,
  MIN(_ingested_at) AS _ingested_at
FROM STREAM bronze_transactions
GROUP BY
  transaction_id,
  customer_id,
  amount,
  transaction_timestamp;
```

---

## Windowed Aggregations

### Tumbling Windows (Fixed, Non-Overlapping)

```sql
-- 5-minute tumbling windows
CREATE OR REPLACE STREAMING TABLE silver_sensor_5min AS
SELECT
  sensor_id,
  window(event_timestamp, '5 minutes') AS time_window,
  AVG(temperature) AS avg_temperature,
  MIN(temperature) AS min_temperature,
  MAX(temperature) AS max_temperature,
  COUNT(*) AS event_count
FROM STREAM bronze_sensor_events
GROUP BY
  sensor_id,
  window(event_timestamp, '5 minutes');
```

### Multiple Window Sizes

```sql
-- 1-minute windows for real-time monitoring
CREATE OR REPLACE STREAMING TABLE gold_sensor_1min AS
SELECT
  sensor_id,
  window(event_timestamp, '1 minute').start AS window_start,
  window(event_timestamp, '1 minute').end AS window_end,
  AVG(value) AS avg_value,
  COUNT(*) AS event_count
FROM STREAM silver_sensor_data
GROUP BY sensor_id, window(event_timestamp, '1 minute');

-- 1-hour windows for trend analysis
CREATE OR REPLACE STREAMING TABLE gold_sensor_1hour AS
SELECT
  sensor_id,
  window(event_timestamp, '1 hour').start AS window_start,
  AVG(value) AS avg_value,
  STDDEV(value) AS stddev_value
FROM STREAM silver_sensor_data
GROUP BY sensor_id, window(event_timestamp, '1 hour');
```

### Alternative: Date/Time Truncation

For simpler cases, use date_trunc instead of window():

```sql
-- Aggregate by minute using date_trunc
CREATE OR REPLACE STREAMING TABLE silver_events_by_minute AS
SELECT
  date_trunc('minute', event_timestamp) AS time_bucket,
  event_type,
  COUNT(*) AS event_count,
  COUNT(DISTINCT user_id) AS unique_users
FROM STREAM bronze_events
GROUP BY
  date_trunc('minute', event_timestamp),
  event_type;

-- Aggregate by hour
CREATE OR REPLACE STREAMING TABLE gold_events_hourly AS
SELECT
  date_trunc('hour', event_timestamp) AS hour,
  SUM(event_count) AS total_events,
  SUM(unique_users) AS total_unique_users
FROM silver_events_by_minute
GROUP BY date_trunc('hour', event_timestamp);
```

---

## Late-Arriving Data Handling

### Event-Time vs Processing-Time

Always use event timestamp (from the data) rather than ingestion timestamp for time-based operations:

```sql
-- ✅ Good: Use event timestamp for business logic
CREATE OR REPLACE STREAMING TABLE silver_orders AS
SELECT
  order_id,
  order_timestamp,  -- From source data (event time)
  customer_id,
  amount,
  _ingested_at      -- Processing time (for debugging only)
FROM STREAM bronze_orders;

-- Group by event time, not processing time
CREATE OR REPLACE STREAMING TABLE gold_daily_orders AS
SELECT
  CAST(order_timestamp AS DATE) AS order_date,  -- Event time
  COUNT(*) AS order_count,
  SUM(amount) AS total_amount
FROM STREAM silver_orders
GROUP BY CAST(order_timestamp AS DATE);
```

### Handling Out-of-Order Events with SCD2

For dimensional data with out-of-order updates, use SEQUENCE BY with event timestamp:

```sql
CREATE OR REFRESH STREAMING TABLE silver_customers_history;

CREATE FLOW customers_scd2_flow AS
AUTO CDC INTO silver_customers_history
FROM stream(bronze_customer_cdc)
KEYS (customer_id)
SEQUENCE BY event_timestamp  -- Use event time, handles out-of-order
APPLY AS DELETE WHEN operation = "DELETE"
COLUMNS * EXCEPT (operation, _rescued_data)
STORED AS SCD TYPE 2
TRACK HISTORY ON *;
```

### Buffering for Late Events

Use larger aggregation windows to tolerate late arrivals:

```sql
-- Aggregate with 5-minute windows but keep state for 1 hour
-- to accommodate late-arriving events
CREATE OR REPLACE STREAMING TABLE silver_metrics_with_lateness AS
SELECT
  metric_name,
  window(event_timestamp, '5 minutes') AS time_window,
  AVG(metric_value) AS avg_value,
  COUNT(*) AS event_count
FROM STREAM bronze_metrics
GROUP BY
  metric_name,
  window(event_timestamp, '5 minutes');
```

---

## Stateful Operations

### Stream-to-Stream Joins

Join two streaming sources on a common key:

```sql
-- Stream 1: Order events
CREATE OR REPLACE STREAMING TABLE bronze_orders AS
SELECT * FROM read_stream(...);

-- Stream 2: Payment events
CREATE OR REPLACE STREAMING TABLE bronze_payments AS
SELECT * FROM read_stream(...);

-- Join streams (inner join)
CREATE OR REPLACE STREAMING TABLE silver_orders_with_payments AS
SELECT
  o.order_id,
  o.customer_id,
  o.order_timestamp,
  o.amount AS order_amount,
  p.payment_id,
  p.payment_timestamp,
  p.payment_method,
  p.amount AS payment_amount
FROM STREAM bronze_orders o
INNER JOIN STREAM bronze_payments p
  ON o.order_id = p.order_id
  AND p.payment_timestamp BETWEEN o.order_timestamp AND o.order_timestamp + INTERVAL 1 HOUR;
```

### Stream-to-Static Joins

Enrich streaming data with static dimension tables:

```sql
-- Static dimension (changes infrequently)
CREATE OR REPLACE TABLE dim_products AS
SELECT * FROM catalog.schema.products;

-- Stream-to-static join
CREATE OR REPLACE STREAMING TABLE silver_sales_enriched AS
SELECT
  s.sale_id,
  s.product_id,
  s.quantity,
  s.sale_timestamp,
  p.product_name,
  p.category,
  p.price,
  s.quantity * p.price AS total_amount
FROM STREAM bronze_sales s
LEFT JOIN dim_products p
  ON s.product_id = p.product_id;
```

### Incremental Aggregations

Build aggregations incrementally as new data arrives:

```sql
-- Running totals by customer
CREATE OR REPLACE STREAMING TABLE silver_customer_running_totals AS
SELECT
  customer_id,
  SUM(amount) AS total_spent,
  COUNT(*) AS transaction_count,
  MAX(transaction_timestamp) AS last_transaction_at
FROM STREAM bronze_transactions
GROUP BY customer_id;

-- This materializes as a stateful aggregation that updates incrementally
```

---

## Session Windows

Group events into sessions based on inactivity gaps:

```sql
-- Group user events into sessions (30-minute inactivity timeout)
CREATE OR REPLACE STREAMING TABLE silver_user_sessions AS
SELECT
  user_id,
  session_window(event_timestamp, '30 minutes') AS session,
  MIN(event_timestamp) AS session_start,
  MAX(event_timestamp) AS session_end,
  COUNT(*) AS event_count,
  COLLECT_LIST(event_type) AS event_sequence
FROM STREAM bronze_user_events
GROUP BY
  user_id,
  session_window(event_timestamp, '30 minutes');
```

---

## Filtering and Outlier Detection

### Real-Time Anomaly Detection

```sql
-- Calculate rolling statistics for anomaly detection
CREATE OR REPLACE STREAMING TABLE silver_sensor_with_anomalies AS
SELECT
  sensor_id,
  event_timestamp,
  temperature,
  AVG(temperature) OVER (
    PARTITION BY sensor_id
    ORDER BY event_timestamp
    ROWS BETWEEN 100 PRECEDING AND CURRENT ROW
  ) AS rolling_avg_100,
  STDDEV(temperature) OVER (
    PARTITION BY sensor_id
    ORDER BY event_timestamp
    ROWS BETWEEN 100 PRECEDING AND CURRENT ROW
  ) AS rolling_stddev_100,
  CASE
    WHEN temperature > rolling_avg_100 + (3 * rolling_stddev_100) THEN 'HIGH_OUTLIER'
    WHEN temperature < rolling_avg_100 - (3 * rolling_stddev_100) THEN 'LOW_OUTLIER'
    ELSE 'NORMAL'
  END AS anomaly_flag
FROM STREAM bronze_sensor_events;

-- Route anomalies to alert table
CREATE OR REPLACE STREAMING TABLE silver_sensor_anomalies AS
SELECT *
FROM STREAM silver_sensor_with_anomalies
WHERE anomaly_flag IN ('HIGH_OUTLIER', 'LOW_OUTLIER');
```

### Threshold-Based Filtering

```sql
-- Filter for high-value transactions
CREATE OR REPLACE STREAMING TABLE silver_high_value_transactions AS
SELECT
  transaction_id,
  customer_id,
  amount,
  transaction_timestamp
FROM STREAM bronze_transactions
WHERE amount > 10000;
```

---

## Continuous vs Triggered Execution

### Continuous Mode (Real-Time)

For sub-second latency requirements, configure pipeline for continuous execution.
Set at pipeline level (not in SQL):

```yaml
# In pipeline configuration
execution_mode: continuous
serverless: true
```

### Triggered Mode (Batch)

For scheduled processing with lower cost:

```yaml
# In pipeline configuration
execution_mode: triggered
schedule: "0 * * * *"  # Hourly
```

**When to use each**:
- **Continuous**: Real-time dashboards, alerting, sub-minute latency SLAs
- **Triggered**: Daily/hourly reports, batch processing, cost optimization

---

## Best Practices

### 1. Always Use Event Timestamps

```sql
-- ✅ Good: Event timestamp for business logic
GROUP BY date_trunc('hour', event_timestamp)

-- ❌ Avoid: Processing timestamp for business logic
GROUP BY date_trunc('hour', _ingested_at)
```

### 2. Choose Appropriate Window Sizes

- **1-5 minutes**: Real-time monitoring, alerting
- **15-60 minutes**: Operational dashboards
- **1-24 hours**: Analytical reports

### 3. Handle State Size Growth

For windowed aggregations, state grows with window size and cardinality:

```sql
-- Higher cardinality = more state
GROUP BY customer_id, product_id, window(...)  -- State per customer-product-window

-- Lower cardinality = less state
GROUP BY region, window(...)  -- State per region-window
```

### 4. Deduplicate Early

Apply deduplication at bronze → silver transition to reduce downstream processing:

```sql
-- Bronze: Accept duplicates
CREATE OR REPLACE STREAMING TABLE bronze_events AS
SELECT * FROM read_stream(...);

-- Silver: Deduplicate immediately
CREATE OR REPLACE STREAMING TABLE silver_events AS
SELECT DISTINCT
  event_id,
  event_type,
  event_timestamp,
  user_id
FROM STREAM bronze_events;

-- Gold: Work with clean data
CREATE OR REPLACE STREAMING TABLE gold_metrics AS
SELECT ... FROM STREAM silver_events;
```

### 5. Monitor Streaming Lag

Track processing delays for streaming sources:

```sql
CREATE OR REPLACE STREAMING TABLE monitoring_lag AS
SELECT
  'kafka_events' AS source,
  MAX(kafka_timestamp) AS max_event_timestamp,
  current_timestamp() AS processing_timestamp,
  (unix_timestamp(current_timestamp()) - unix_timestamp(MAX(kafka_timestamp))) AS lag_seconds
FROM STREAM bronze_kafka_events
GROUP BY window(kafka_timestamp, '1 minute');
```

---

## Common Issues and Solutions

### Issue: High memory usage with windowed aggregations
**Cause**: Too many windows or high cardinality grouping
**Solution**: Use larger windows, reduce group-by cardinality, or use materialized views

### Issue: Duplicate events in output
**Cause**: No deduplication or restarts replaying data
**Solution**: Add explicit deduplication in silver layer by unique key

### Issue: Missing late-arriving events in aggregations
**Cause**: Window closed before late events arrived
**Solution**: Increase window size or use date_trunc for longer retention

### Issue: Stream-to-stream join producing no results
**Cause**: Time range conditions too restrictive or keys don't match
**Solution**: Verify join conditions and inspect both streams separately
