# Data Ingestion Patterns for SDP

## Overview

This guide covers data ingestion patterns for Lakeflow Spark Declarative Pipelines, including Auto Loader for cloud storage and streaming sources like Kafka and Event Hub.

**Language Support**:
- **SQL**: Examples below use SQL syntax (primary focus)
- **Python**: For Python syntax using modern `pyspark.pipelines` API, see:
  - [Official Python Transform Documentation](https://docs.databricks.com/aws/en/ldp/transform/?language=Python)
  - Local skill file: `python-api-versions.md` for migration from legacy `dlt` to modern `dp` API

---

## Auto Loader (Cloud Files)

Auto Loader incrementally and efficiently processes new data files as they arrive in cloud storage.

### Basic Auto Loader Pattern

```sql
CREATE OR REPLACE STREAMING TABLE bronze_orders AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  _metadata.file_path AS source_file,
  _metadata.file_modification_time AS file_timestamp
FROM read_files(
  '/mnt/raw/orders/',
  format => 'json',
  schemaHints => 'order_id STRING, amount DECIMAL(10,2)'
);
```

### Auto Loader with Schema Evolution

```sql
CREATE OR REPLACE STREAMING TABLE bronze_customers AS
SELECT
  *,
  current_timestamp() AS _ingested_at
FROM read_files(
  '/mnt/raw/customers/',
  format => 'json',
  schemaHints => 'customer_id STRING, email STRING',
  mode => 'PERMISSIVE'  -- Handles schema changes gracefully
);
```

### Common File Formats

**JSON Files**:
```sql
FROM read_files(
  's3://bucket/data/',
  format => 'json',
  schemaHints => 'id STRING, timestamp TIMESTAMP'
)
```

**CSV Files**:
```sql
FROM read_files(
  '/mnt/raw/data/',
  format => 'csv',
  schemaHints => 'id STRING, name STRING, amount DECIMAL(10,2)',
  header => true,
  delimiter => ','
)
```

**Parquet Files**:
```sql
FROM read_files(
  'abfss://container@storage.dfs.core.windows.net/data/',
  format => 'parquet'
)
```

**Avro Files**:
```sql
FROM read_files(
  '/mnt/raw/events/',
  format => 'avro',
  schemaHints => 'event_id STRING, event_time TIMESTAMP'
)
```

### Schema Inference and Hints

**Explicit Schema Hints** (recommended for production):
```sql
CREATE OR REPLACE STREAMING TABLE bronze_sales AS
SELECT
  *,
  current_timestamp() AS _ingested_at
FROM read_files(
  '/mnt/raw/sales/',
  format => 'json',
  schemaHints => 'sale_id STRING, customer_id STRING, amount DECIMAL(10,2), sale_date DATE'
);
```

**Partial Schema Hints** (infer remaining columns):
```sql
FROM read_files(
  '/mnt/raw/data/',
  format => 'json',
  schemaHints => 'id STRING, critical_field DECIMAL(10,2)'  -- Other fields auto-inferred
)
```

### File Notification Modes

**Directory Listing** (default, good for small directories):
```sql
FROM read_files(
  '/mnt/raw/data/',
  format => 'json'
  -- Uses directory listing to discover files
)
```

**File Notification** (better for large directories):
Configure at the pipeline level for better performance with large directories.

### Rescue Data Column

Handle malformed records with `_rescued_data`:

```sql
CREATE OR REPLACE STREAMING TABLE bronze_events AS
SELECT
  *,
  current_timestamp() AS _ingested_at,
  CASE WHEN _rescued_data IS NOT NULL THEN TRUE ELSE FALSE END AS has_parsing_errors
FROM read_files(
  '/mnt/raw/events/',
  format => 'json',
  schemaHints => 'event_id STRING, event_time TIMESTAMP'
);

-- Create quarantine table for records with rescue data
CREATE OR REPLACE STREAMING TABLE bronze_events_quarantine AS
SELECT *
FROM STREAM bronze_events
WHERE _rescued_data IS NOT NULL;
```

### Incremental Processing

Auto Loader automatically maintains checkpoints and processes only new files:

```sql
-- Bronze layer processes new files incrementally
CREATE OR REPLACE STREAMING TABLE bronze_transactions AS
SELECT *
FROM read_files(
  '/mnt/raw/transactions/',
  format => 'json'
);

-- Silver layer processes new bronze records incrementally
CREATE OR REPLACE STREAMING TABLE silver_transactions AS
SELECT
  transaction_id,
  CAST(amount AS DECIMAL(10,2)) AS amount,
  CAST(transaction_date AS DATE) AS transaction_date
FROM STREAM bronze_transactions
WHERE transaction_id IS NOT NULL;
```

---

## Streaming Sources (Kafka, Event Hub, Kinesis)

### Kafka Source

```sql
CREATE OR REPLACE STREAMING TABLE bronze_kafka_events AS
SELECT
  CAST(key AS STRING) AS event_key,
  CAST(value AS STRING) AS event_value,
  topic,
  partition,
  offset,
  timestamp AS kafka_timestamp,
  current_timestamp() AS _ingested_at
FROM read_stream(
  format => 'kafka',
  kafka.bootstrap.servers => '${kafka_brokers}',
  subscribe => 'events-topic',
  startingOffsets => 'latest',  -- or 'earliest'
  kafka.security.protocol => 'SASL_SSL',
  kafka.sasl.mechanism => 'PLAIN',
  kafka.sasl.jaas.config => 'kafkashaded.org.apache.kafka.common.security.plain.PlainLoginModule required username="${kafka_username}" password="${kafka_password}";'
);
```

### Kafka with Multiple Topics

```sql
CREATE OR REPLACE STREAMING TABLE bronze_kafka_multi AS
SELECT
  CAST(value AS STRING) AS event_value,
  topic,
  timestamp AS kafka_timestamp
FROM read_stream(
  format => 'kafka',
  kafka.bootstrap.servers => '${kafka_brokers}',
  subscribe => 'topic1,topic2,topic3',
  startingOffsets => 'latest'
);
```

### Azure Event Hub

```sql
CREATE OR REPLACE STREAMING TABLE bronze_eventhub_events AS
SELECT
  CAST(body AS STRING) AS event_body,
  enqueuedTime AS event_time,
  offset,
  sequenceNumber,
  current_timestamp() AS _ingested_at
FROM read_stream(
  format => 'eventhubs',
  eventhubs.connectionString => '${eventhub_connection_string}',
  eventhubs.consumerGroup => '${consumer_group}',
  startingPosition => 'latest'  -- or specific timestamp
);
```

### AWS Kinesis

```sql
CREATE OR REPLACE STREAMING TABLE bronze_kinesis_events AS
SELECT
  CAST(data AS STRING) AS event_data,
  partitionKey,
  sequenceNumber,
  approximateArrivalTimestamp AS arrival_time,
  current_timestamp() AS _ingested_at
FROM read_stream(
  format => 'kinesis',
  kinesis.streamName => '${stream_name}',
  kinesis.region => '${aws_region}',
  kinesis.startingPosition => 'LATEST'
);
```

### Parse JSON from Streaming Sources

```sql
-- Parse JSON from Kafka value
CREATE OR REPLACE STREAMING TABLE silver_kafka_parsed AS
SELECT
  from_json(
    event_value,
    'event_id STRING, event_type STRING, user_id STRING, timestamp TIMESTAMP, properties MAP<STRING, STRING>'
  ) AS event_data,
  kafka_timestamp,
  _ingested_at
FROM STREAM bronze_kafka_events;

-- Flatten the parsed JSON
CREATE OR REPLACE STREAMING TABLE silver_kafka_flattened AS
SELECT
  event_data.event_id,
  event_data.event_type,
  event_data.user_id,
  event_data.timestamp AS event_timestamp,
  event_data.properties,
  kafka_timestamp,
  _ingested_at
FROM STREAM silver_kafka_parsed;
```

---

## Authentication Patterns

### Using Databricks Secrets

**For Kafka**:
```sql
kafka.sasl.jaas.config => 'kafkashaded.org.apache.kafka.common.security.plain.PlainLoginModule required username="{{secrets/kafka/username}}" password="{{secrets/kafka/password}}";'
```

**For Event Hub**:
```sql
eventhubs.connectionString => '{{secrets/eventhub/connection-string}}'
```

### Using Pipeline Variables

Define variables in pipeline configuration and reference them:

```sql
-- In pipeline SQL, reference variables
kafka.bootstrap.servers => '${kafka_brokers}'
```

Then set in pipeline YAML or UI:
```yaml
variables:
  kafka_brokers:
    default: "broker1:9092,broker2:9092"
```

---

## Best Practices

### 1. Always Add Ingestion Timestamp

```sql
SELECT
  *,
  current_timestamp() AS _ingested_at
FROM read_files(...)
```

### 2. Include File Metadata for Debugging

```sql
SELECT
  *,
  _metadata.file_path AS source_file,
  _metadata.file_modification_time AS file_timestamp,
  _metadata.file_size AS file_size
FROM read_files(...)
```

### 3. Use Schema Hints for Production

```sql
-- ✅ Good: Explicit schema hints prevent surprises
FROM read_files(
  '/mnt/data/',
  format => 'json',
  schemaHints => 'id STRING, amount DECIMAL(10,2), date DATE'
)

-- ❌ Avoid: Fully inferred schemas can drift unexpectedly
FROM read_files('/mnt/data/', format => 'json')
```

### 4. Handle Rescue Data for Data Quality

```sql
CREATE OR REPLACE STREAMING TABLE bronze_data AS
SELECT
  *,
  CASE WHEN _rescued_data IS NOT NULL THEN TRUE ELSE FALSE END AS has_errors
FROM read_files(...);

-- Route errors to quarantine
CREATE OR REPLACE STREAMING TABLE bronze_data_quarantine AS
SELECT * FROM STREAM bronze_data WHERE has_errors;

-- Clean data for downstream
CREATE OR REPLACE STREAMING TABLE silver_data AS
SELECT * FROM STREAM bronze_data WHERE NOT has_errors;
```

### 5. Use Appropriate Starting Positions

**For Kafka/Event Hub**:
- Development: `startingOffsets => 'latest'` (process new data only)
- Backfill: `startingOffsets => 'earliest'` (process all available data)
- Recovery: Checkpoints handle this automatically

---

## Common Issues and Solutions

### Issue: Files not being picked up
**Cause**: File format mismatch or incorrect path
**Solution**: Verify format matches actual files and path is correct

### Issue: Schema evolution breaking pipeline
**Cause**: New columns added to source files
**Solution**: Use `mode => 'PERMISSIVE'` and monitor `_rescued_data`

### Issue: Kafka lag increasing
**Cause**: Processing slower than ingestion rate
**Solution**: Check downstream transformations for bottlenecks, consider increasing parallelism

### Issue: Duplicate events from streaming sources
**Cause**: At-least-once semantics from source
**Solution**: Implement deduplication in silver layer with GROUP BY or ROW_NUMBER()

---

## Python API Examples

For Python implementations, use the modern `pyspark.pipelines` API (`dp`), not the legacy `dlt` API.

### Basic Auto Loader Pattern (Python)

```python
from pyspark import pipelines as dp
from pyspark.sql import functions as F

@dp.table(
    name="bronze_orders",
    cluster_by=["order_date"]
)
def bronze_orders():
    """Ingest raw orders using Auto Loader"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", "/checkpoints/bronze_orders")
        .option("cloudFiles.schemaHints", "order_id STRING, amount DECIMAL(10,2)")
        .load("/mnt/raw/orders/")
        .withColumn("_ingested_at", F.current_timestamp())
        .withColumn("_source_file", F.col("_metadata.file_path"))
    )
```

### Kafka Source (Python)

```python
@dp.table(name="bronze_kafka_events")
def bronze_kafka_events():
    """Ingest events from Kafka"""
    return (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", spark.conf.get("kafka_brokers"))
        .option("subscribe", "events-topic")
        .option("startingOffsets", "latest")
        .load()
        .selectExpr(
            "CAST(key AS STRING) AS event_key",
            "CAST(value AS STRING) AS event_value",
            "topic",
            "partition",
            "offset",
            "timestamp AS kafka_timestamp"
        )
        .withColumn("_ingested_at", F.current_timestamp())
    )
```

### Quarantine Pattern (Python)

```python
@dp.table(
    name="bronze_events",
    cluster_by=["ingestion_date"]
)
def bronze_events():
    """Bronze layer with rescue data for error handling"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("rescuedDataColumn", "_rescued_data")
        .load("/mnt/raw/events/")
        .withColumn("_ingested_at", F.current_timestamp())
        .withColumn("ingestion_date", F.current_date())
        .withColumn("_has_parsing_errors",
                   F.when(F.col("_rescued_data").isNotNull(), True)
                   .otherwise(False))
    )

@dp.table(name="bronze_events_quarantine")
def bronze_events_quarantine():
    """Isolate malformed records"""
    return (
        dp.read.table("catalog.schema.bronze_events")
        .filter(F.col("_has_parsing_errors") == True)
    )
```

**For Python API reference**: [Official Python Transform Documentation](https://docs.databricks.com/aws/en/ldp/transform/?language=Python)
