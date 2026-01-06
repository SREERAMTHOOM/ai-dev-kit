# SCD Query Patterns

## Overview

This guide covers how to query SCD Type 2 history tables effectively, including current state queries, point-in-time analysis, and change tracking.

---

## Understanding SCD Type 2 Structure

When you create an SCD Type 2 flow, the system automatically adds temporal columns:

```sql
CREATE FLOW customers_scd2_flow AS
AUTO CDC INTO customers_history
FROM stream(customers_cdc_clean)
KEYS (customer_id)
SEQUENCE BY event_timestamp
STORED AS SCD TYPE 2
TRACK HISTORY ON *;
```

**Resulting table structure**:
```
customers_history
├── customer_id        -- Business key
├── customer_name
├── email
├── phone
├── START_AT          -- When this version became effective (auto-generated)
├── END_AT            -- When this version expired (NULL for current)
└── ...other columns
```

---

## Current State Queries

### Get Current Version of All Records

```sql
-- Current state: END_AT IS NULL indicates active record
CREATE OR REPLACE MATERIALIZED VIEW dim_customers_current AS
SELECT
  customer_id,
  customer_name,
  email,
  phone,
  address,
  START_AT AS valid_from
FROM customers_history
WHERE END_AT IS NULL;
```

### Get Current Version for Specific Customer

```sql
SELECT
  *
FROM customers_history
WHERE customer_id = '12345'
  AND END_AT IS NULL;
```

---

## Point-in-Time Queries

### As-Of Date Query

Get the state of records as they were on a specific date:

```sql
-- Products as they were on January 1, 2024
CREATE OR REPLACE MATERIALIZED VIEW products_as_of_2024_01_01 AS
SELECT
  product_id,
  product_name,
  price,
  category,
  START_AT,
  END_AT
FROM products_history
WHERE START_AT <= '2024-01-01'
  AND (END_AT > '2024-01-01' OR END_AT IS NULL);
```

---

## Change Analysis

### Track All Changes for an Entity

```sql
-- See complete history of changes for a customer
SELECT
  customer_id,
  customer_name,
  email,
  phone,
  START_AT,
  END_AT,
  COALESCE(
    DATEDIFF(DAY, START_AT, END_AT),
    DATEDIFF(DAY, START_AT, CURRENT_TIMESTAMP())
  ) AS days_active
FROM customers_history
WHERE customer_id = '12345'
ORDER BY START_AT DESC;
```

### Changes Within a Time Period

```sql
-- Customers who changed during Q1 2024
SELECT
  customer_id,
  customer_name,
  START_AT AS change_timestamp,
  'UPDATE' AS change_type
FROM customers_history
WHERE START_AT BETWEEN '2024-01-01' AND '2024-03-31'
  AND START_AT != (
    SELECT MIN(START_AT)
    FROM customers_history ch2
    WHERE ch2.customer_id = customers_history.customer_id
  )
ORDER BY START_AT;
```

---

## Joining Facts with Historical Dimensions

### Enrich Facts with Dimension State at Transaction Time

```sql
-- Join sales with product prices as they were at the time of sale
CREATE OR REPLACE MATERIALIZED VIEW sales_with_historical_prices AS
SELECT
  s.sale_id,
  s.product_id,
  s.sale_date,
  s.quantity,
  p.product_name,
  p.price AS unit_price_at_sale_time,
  s.quantity * p.price AS calculated_amount,
  p.category
FROM sales_fact s
INNER JOIN products_history p
  ON s.product_id = p.product_id
  AND s.sale_date >= p.START_AT
  AND (s.sale_date < p.END_AT OR p.END_AT IS NULL);
```

### Join with Current Dimension State

```sql
-- Join sales with current product information
CREATE OR REPLACE MATERIALIZED VIEW sales_with_current_prices AS
SELECT
  s.sale_id,
  s.product_id,
  s.sale_date,
  s.quantity,
  s.amount AS amount_at_sale,
  p.product_name AS current_product_name,
  p.price AS current_price,
  p.category AS current_category
FROM sales_fact s
INNER JOIN products_history p
  ON s.product_id = p.product_id
  AND p.END_AT IS NULL;  -- Current version only
```

---

## Selective History Tracking Queries

When using `TRACK HISTORY ON specific_columns`:

```sql
-- Example: Only tracking price changes for products
CREATE FLOW products_scd2_flow AS
AUTO CDC INTO products_history
FROM stream(products_cdc_clean)
KEYS (product_id)
SEQUENCE BY event_timestamp
STORED AS SCD TYPE 2
TRACK HISTORY ON price, cost;  -- Only these columns trigger new versions
```
---

## Performance Optimization

### 1. Create Filtered Materialized Views

```sql
-- Current state view (most common query pattern)
CREATE OR REPLACE MATERIALIZED VIEW dim_products_current AS
SELECT * FROM products_history WHERE END_AT IS NULL;

-- Pre-aggregate change frequencies
CREATE OR REPLACE MATERIALIZED VIEW product_change_stats AS
SELECT
  product_id,
  COUNT(*) AS version_count,
  MIN(START_AT) AS first_seen,
  MAX(START_AT) AS last_updated
FROM products_history
GROUP BY product_id;
```

---

## Best Practices

### 1. Always Filter by END_AT for Current State

```sql
-- ✅ Correct: Filter for current records
WHERE END_AT IS NULL

-- ❌ Incorrect: Using MAX(START_AT) is less efficient
WHERE START_AT = (SELECT MAX(START_AT) FROM table WHERE ...)
```

### 2. Use Inclusive Lower Bound, Exclusive Upper Bound

```sql
-- ✅ Standard pattern for point-in-time
WHERE START_AT <= '2024-01-01'
  AND (END_AT > '2024-01-01' OR END_AT IS NULL)
```

### 3. Create Materialized Views for Common Patterns

```sql
-- Current state
CREATE OR REPLACE MATERIALIZED VIEW dim_current AS
SELECT * FROM history WHERE END_AT IS NULL;

-- Recent changes (last 90 days)
CREATE OR REPLACE MATERIALIZED VIEW dim_recent_changes AS
SELECT * FROM history
WHERE START_AT >= CURRENT_DATE() - INTERVAL 90 DAYS;
```


---

## Common Issues and Solutions

### Issue: Query returns multiple rows for same key
**Cause**: Missing END_AT IS NULL filter for current state
**Solution**: Add `WHERE END_AT IS NULL` for current state queries

### Issue: Point-in-time query returns no results
**Cause**: Incorrect date comparison logic
**Solution**: Use `START_AT <= date AND (END_AT > date OR END_AT IS NULL)`

### Issue: Temporal join is very slow
**Cause**: Full table scan on history table
**Solution**: Create materialized view for specific time period or add partitioning

### Issue: Change analysis shows unexpected duplicates
**Cause**: Multiple changes on same day or timestamp precision issues
**Solution**: Use SEQUENCE BY with high precision or add sequence number for tie-breaking
