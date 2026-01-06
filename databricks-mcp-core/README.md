# Databricks MCP Core

High-level, AI-assistant-friendly Python functions for building Databricks projects.

## Overview

The `databricks-mcp-core` package provides reusable, opinionated functions for interacting with the Databricks platform. It is designed to be used by AI coding assistants (Claude Code, Cursor, etc.) and developers who want simple, high-level APIs for common Databricks operations.

### Modules

| Module | Description |
|--------|-------------|
| **sql/** | SQL execution, warehouse management, and table statistics |
| **unity_catalog/** | Unity Catalog operations (catalogs, schemas, tables) |
| **compute/** | Compute and execution context operations |
| **spark_declarative_pipelines/** | Spark Declarative Pipeline management |
| **synthetic_data_generation/** | Test data generation utilities |

## Installation

### Using uv (recommended)

```bash
# Install the package
uv pip install -e .

# Install with dev dependencies
uv pip install -e ".[dev]"
```

### Using pip

```bash
pip install -e .
```

## Authentication

All functions use the official `databricks-sdk` and handle authentication automatically via:

1. **Environment variables**: `DATABRICKS_HOST` and `DATABRICKS_TOKEN`
2. **Config profile**: `DATABRICKS_CONFIG_PROFILE` or `~/.databrickscfg`

```bash
# Option 1: Environment variables
export DATABRICKS_HOST="https://your-workspace.cloud.databricks.com"
export DATABRICKS_TOKEN="your-token"

# Option 2: Config profile
export DATABRICKS_CONFIG_PROFILE="my-profile"
```

## Usage

### SQL Execution

Execute SQL queries on Databricks SQL Warehouses:

```python
from databricks_mcp_core.sql import execute_sql, execute_sql_multi

# Simple query (auto-selects warehouse if not specified)
result = execute_sql("SELECT * FROM my_catalog.my_schema.customers LIMIT 10")
# Returns: [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}, ...]

# Query with specific warehouse and catalog/schema context
result = execute_sql(
    sql_query="SELECT COUNT(*) as cnt FROM customers",
    warehouse_id="abc123def456",
    catalog="my_catalog",
    schema="my_schema",
)

# Execute multiple statements with dependency-aware parallelism
result = execute_sql_multi(
    sql_content="""
        CREATE TABLE t1 AS SELECT 1 as id;
        CREATE TABLE t2 AS SELECT 2 as id;
        CREATE TABLE t3 AS SELECT * FROM t1 JOIN t2;
    """,
    catalog="my_catalog",
    schema="my_schema",
)
# t1 and t2 run in parallel, t3 waits for both
```

### Warehouse Management

List and select SQL warehouses:

```python
from databricks_mcp_core.sql import list_warehouses, get_best_warehouse

# List warehouses (running ones first)
warehouses = list_warehouses(limit=20)
# Returns: [{"id": "...", "name": "...", "state": "RUNNING", ...}, ...]

# Auto-select best available warehouse
warehouse_id = get_best_warehouse()
# Prefers: running shared endpoints > running warehouses > stopped warehouses
```

### Table Statistics

Get detailed table information and column statistics:

```python
from databricks_mcp_core.sql import get_table_details, TableStatLevel

# Get all tables in a schema with basic stats
result = get_table_details(
    catalog="my_catalog",
    schema="my_schema",
)

# Get specific tables (faster - no listing required)
result = get_table_details(
    catalog="my_catalog",
    schema="my_schema",
    table_names=["customers", "orders"],
)

# Use glob patterns
result = get_table_details(
    catalog="my_catalog",
    schema="my_schema",
    table_names=["raw_*", "gold_customers"],  # Mix of patterns and exact names
)

# Control stat level
result = get_table_details(
    catalog="my_catalog",
    schema="my_schema",
    table_names=["customers"],
    table_stat_level=TableStatLevel.DETAILED,  # NONE, SIMPLE, or DETAILED
)
```

**TableStatLevel options:**

| Level | Description | Use Case |
|-------|-------------|----------|
| `NONE` | DDL only, no stats | Quick schema lookup |
| `SIMPLE` | Basic stats (samples, min/max, cardinality) | Default, cached |
| `DETAILED` | Full stats (histograms, percentiles, value counts) | Data profiling |

### Unity Catalog Operations

```python
from databricks_mcp_core.unity_catalog import catalogs, schemas, tables

# List catalogs
all_catalogs = catalogs.list_catalogs()

# Create schema
schema = schemas.create_schema(
    catalog_name="main",
    schema_name="my_schema",
    comment="Example schema"
)

# Create table
from databricks.sdk.service.catalog import ColumnInfo, TableType

table = tables.create_table(
    catalog_name="main",
    schema_name="my_schema",
    table_name="my_table",
    columns=[
        ColumnInfo(name="id", type_name="INT"),
        ColumnInfo(name="value", type_name="STRING")
    ],
    table_type=TableType.MANAGED
)
```

## Architecture

```
databricks-mcp-core/
├── databricks_mcp_core/
│   ├── sql/                          # SQL operations
│   │   ├── sql.py                    # execute_sql, execute_sql_multi
│   │   ├── warehouse.py              # list_warehouses, get_best_warehouse
│   │   ├── table_stats.py            # get_table_details
│   │   └── sql_utils/                # Internal utilities
│   │       ├── executor.py           # SQLExecutor class
│   │       ├── parallel_executor.py  # Multi-statement execution
│   │       ├── dependency_analyzer.py # SQL dependency analysis
│   │       ├── table_stats_collector.py # Stats collection with caching
│   │       └── models.py             # Pydantic models
│   ├── unity_catalog/                # Unity Catalog operations
│   ├── compute/                      # Compute operations
│   ├── spark_declarative_pipelines/  # SDP operations
│   └── client.py                     # REST API client
└── tests/                            # Integration tests
```

This is a **pure Python library** with no MCP protocol dependencies. It can be used standalone in notebooks, scripts, or other Python projects.

For MCP server functionality, see the `databricks-mcp-server` package which wraps these functions as MCP tools.

## Testing

The project includes comprehensive integration tests that run against a real Databricks workspace.

### Prerequisites

- A Databricks workspace with valid authentication configured
- At least one running SQL warehouse
- Permission to create catalogs/schemas/tables

### Running Tests

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run all integration tests
uv run pytest tests/integration/ -v

# Run specific test file
uv run pytest tests/integration/sql/test_sql.py -v

# Run specific test class
uv run pytest tests/integration/sql/test_table_stats.py::TestTableStatLevelDetailed -v

# Run with more verbose output
uv run pytest tests/integration/ -v --tb=long
```

### Test Structure

```
tests/
├── conftest.py                    # Shared fixtures
│   ├── workspace_client           # WorkspaceClient fixture
│   ├── test_catalog               # Creates ai_dev_kit_test catalog
│   ├── test_schema                # Creates fresh test_schema (drops if exists)
│   ├── warehouse_id               # Gets best running warehouse
│   └── test_tables                # Creates sample tables with data
└── integration/
    └── sql/
        ├── test_warehouse.py      # Warehouse listing tests
        ├── test_sql.py            # SQL execution tests
        └── test_table_stats.py    # Table statistics tests
```

### Test Coverage

| Test File | Coverage |
|-----------|----------|
| `test_warehouse.py` | `list_warehouses`, `get_best_warehouse` |
| `test_sql.py` | `execute_sql`, `execute_sql_multi`, error handling, parallel execution |
| `test_table_stats.py` | `get_table_details`, all stat levels, glob patterns, caching |

### Test Fixtures

The test suite uses session-scoped fixtures to minimize setup overhead:

- **`test_catalog`**: Creates `ai_dev_kit_test` catalog (reuses if exists)
- **`test_schema`**: Drops and recreates `test_schema` for clean state
- **`test_tables`**: Creates `customers`, `orders`, `products` tables with sample data

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Format code
uv run black databricks_mcp_core/

# Lint code
uv run ruff check databricks_mcp_core/
```

## Dependencies

### Core
- `databricks-sdk>=0.20.0` - Official Databricks Python SDK
- `requests>=2.31.0` - HTTP client
- `pydantic>=2.0.0` - Data validation
- `sqlglot>=20.0.0` - SQL parsing
- `sqlfluff>=3.0.0` - SQL linting and formatting

### Development
- `pytest>=7.0.0` - Testing framework
- `pytest-timeout>=2.0.0` - Test timeouts
- `black>=23.0.0` - Code formatting
- `ruff>=0.1.0` - Linting
