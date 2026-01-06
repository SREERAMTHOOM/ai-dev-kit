"""
Pytest fixtures for databricks-mcp-core integration tests.

These fixtures set up and tear down test resources in Databricks.
Requires a valid Databricks connection (via env vars or ~/.databrickscfg).
"""

import logging
import os
import pytest
from databricks.sdk import WorkspaceClient

# Test catalog and schema names
TEST_CATALOG = "ai_dev_kit_test"
TEST_SCHEMA = "test_schema"

logger = logging.getLogger(__name__)


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring Databricks"
    )


@pytest.fixture(scope="session")
def workspace_client() -> WorkspaceClient:
    """
    Create a WorkspaceClient for the test session.

    Uses standard Databricks authentication:
    1. DATABRICKS_HOST + DATABRICKS_TOKEN env vars
    2. ~/.databrickscfg profile
    """
    try:
        client = WorkspaceClient()
        # Verify connection works
        client.current_user.me()
        logger.info(f"Connected to Databricks: {client.config.host}")
        return client
    except Exception as e:
        pytest.skip(f"Could not connect to Databricks: {e}")


@pytest.fixture(scope="session")
def test_catalog(workspace_client: WorkspaceClient) -> str:
    """
    Ensure test catalog exists.

    Returns the catalog name.
    """
    try:
        workspace_client.catalogs.get(TEST_CATALOG)
        logger.info(f"Using existing catalog: {TEST_CATALOG}")
    except Exception:
        logger.info(f"Creating catalog: {TEST_CATALOG}")
        workspace_client.catalogs.create(name=TEST_CATALOG)

    return TEST_CATALOG


@pytest.fixture(scope="session")
def test_schema(workspace_client: WorkspaceClient, test_catalog: str) -> str:
    """
    Create a fresh test schema (drops if exists).

    This ensures a clean state for each test run.
    Returns the schema name.
    """
    full_schema_name = f"{test_catalog}.{TEST_SCHEMA}"

    # Drop schema if exists (cascade to remove all objects)
    try:
        logger.info(f"Dropping existing schema: {full_schema_name}")
        workspace_client.schemas.delete(full_schema_name)
    except Exception:
        pass  # Schema doesn't exist, that's fine

    # Create fresh schema
    logger.info(f"Creating schema: {full_schema_name}")
    workspace_client.schemas.create(
        name=TEST_SCHEMA,
        catalog_name=test_catalog,
    )

    yield TEST_SCHEMA

    # Cleanup after all tests (optional - comment out to inspect test data)
    # try:
    #     logger.info(f"Cleaning up schema: {full_schema_name}")
    #     workspace_client.schemas.delete(full_schema_name)
    # except Exception as e:
    #     logger.warning(f"Failed to cleanup schema: {e}")


@pytest.fixture(scope="session")
def warehouse_id(workspace_client: WorkspaceClient) -> str:
    """
    Get a running SQL warehouse for tests.

    Prefers shared endpoints, falls back to any running warehouse.
    """
    from databricks.sdk.service.sql import State

    warehouses = list(workspace_client.warehouses.list())

    # Priority: running shared endpoint
    for w in warehouses:
        if w.state == State.RUNNING and "shared" in (w.name or "").lower():
            logger.info(f"Using warehouse: {w.name} ({w.id})")
            return w.id

    # Fallback: any running warehouse
    for w in warehouses:
        if w.state == State.RUNNING:
            logger.info(f"Using warehouse: {w.name} ({w.id})")
            return w.id

    # No running warehouse found
    pytest.skip("No running SQL warehouse available for tests")


@pytest.fixture(scope="module")
def test_tables(
    workspace_client: WorkspaceClient,
    test_catalog: str,
    test_schema: str,
    warehouse_id: str,
) -> dict:
    """
    Create test tables with sample data.

    Creates:
    - customers: Basic customer table
    - orders: Orders with foreign key to customers
    - products: Product catalog with various data types

    Returns dict with table names.
    """
    from databricks_mcp_core.sql import execute_sql

    tables = {
        "customers": f"{test_catalog}.{test_schema}.customers",
        "orders": f"{test_catalog}.{test_schema}.orders",
        "products": f"{test_catalog}.{test_schema}.products",
    }

    # Create customers table
    execute_sql(
        sql_query=f"""
            CREATE OR REPLACE TABLE {tables['customers']} (
                customer_id BIGINT,
                name STRING,
                email STRING,
                country STRING,
                created_at TIMESTAMP,
                is_active BOOLEAN
            )
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    # Insert customer data
    execute_sql(
        sql_query=f"""
            INSERT INTO {tables['customers']} VALUES
            (1, 'Alice Smith', 'alice@example.com', 'USA', '2024-01-15 10:30:00', true),
            (2, 'Bob Johnson', 'bob@example.com', 'Canada', '2024-02-20 14:45:00', true),
            (3, 'Charlie Brown', 'charlie@example.com', 'UK', '2024-03-10 09:00:00', false),
            (4, 'Diana Ross', 'diana@example.com', 'USA', '2024-04-05 16:20:00', true),
            (5, 'Eve Wilson', 'eve@example.com', 'Germany', '2024-05-12 11:15:00', true)
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    # Create orders table
    execute_sql(
        sql_query=f"""
            CREATE OR REPLACE TABLE {tables['orders']} (
                order_id BIGINT,
                customer_id BIGINT,
                amount DECIMAL(10, 2),
                status STRING,
                order_date DATE
            )
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    # Insert order data
    execute_sql(
        sql_query=f"""
            INSERT INTO {tables['orders']} VALUES
            (101, 1, 150.00, 'completed', '2024-06-01'),
            (102, 1, 75.50, 'completed', '2024-06-15'),
            (103, 2, 200.00, 'pending', '2024-06-20'),
            (104, 3, 50.00, 'cancelled', '2024-06-22'),
            (105, 4, 300.00, 'completed', '2024-06-25'),
            (106, 5, 125.75, 'pending', '2024-06-28'),
            (107, 1, 89.99, 'completed', '2024-07-01'),
            (108, 2, 175.00, 'completed', '2024-07-05')
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    # Create products table with various data types
    execute_sql(
        sql_query=f"""
            CREATE OR REPLACE TABLE {tables['products']} (
                product_id BIGINT,
                name STRING,
                category STRING,
                price DOUBLE,
                stock_quantity INT,
                rating FLOAT,
                tags ARRAY<STRING>,
                created_at TIMESTAMP
            )
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    # Insert product data
    execute_sql(
        sql_query=f"""
            INSERT INTO {tables['products']} VALUES
            (1, 'Laptop Pro', 'Electronics', 1299.99, 50, 4.5, ARRAY('tech', 'computer'), '2024-01-01 00:00:00'),
            (2, 'Wireless Mouse', 'Electronics', 29.99, 200, 4.2, ARRAY('tech', 'accessory'), '2024-01-15 00:00:00'),
            (3, 'Coffee Maker', 'Kitchen', 79.99, 75, 4.8, ARRAY('home', 'appliance'), '2024-02-01 00:00:00'),
            (4, 'Running Shoes', 'Sports', 119.99, 100, 4.3, ARRAY('fitness', 'footwear'), '2024-02-15 00:00:00'),
            (5, 'Desk Lamp', 'Office', 45.00, 150, 4.0, ARRAY('home', 'lighting'), '2024-03-01 00:00:00')
        """,
        warehouse_id=warehouse_id,
        catalog=test_catalog,
        schema=test_schema,
    )

    logger.info(f"Created test tables: {list(tables.keys())}")
    return tables
