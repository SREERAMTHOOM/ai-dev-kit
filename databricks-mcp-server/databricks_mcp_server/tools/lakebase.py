"""Lakebase tools - Manage Lakebase Provisioned instances, catalogs, and synced tables."""

from typing import Any, Dict, List, Optional

from databricks_tools_core.lakebase import (
    create_lakebase_instance as _create_lakebase_instance,
    get_lakebase_instance as _get_lakebase_instance,
    list_lakebase_instances as _list_lakebase_instances,
    update_lakebase_instance as _update_lakebase_instance,
    delete_lakebase_instance as _delete_lakebase_instance,
    generate_lakebase_credential as _generate_lakebase_credential,
    create_lakebase_catalog as _create_lakebase_catalog,
    get_lakebase_catalog as _get_lakebase_catalog,
    delete_lakebase_catalog as _delete_lakebase_catalog,
    create_synced_table as _create_synced_table,
    get_synced_table as _get_synced_table,
    delete_synced_table as _delete_synced_table,
)

from ..server import mcp


# ============================================================================
# Instance Management Tools
# ============================================================================


@mcp.tool
def create_lakebase_instance(
    name: str,
    capacity: str = "CU_1",
    stopped: bool = False,
) -> Dict[str, Any]:
    """
    Create a Lakebase Provisioned (managed PostgreSQL) database instance.

    Lakebase provides a fully managed PostgreSQL-compatible database
    for OLTP workloads, integrated with Unity Catalog and OAuth authentication.

    Args:
        name: Instance name (1-63 characters, letters and hyphens only)
        capacity: Compute capacity: "CU_1", "CU_2", "CU_4", or "CU_8"
        stopped: If True, create in stopped state (default: False)

    Returns:
        Dictionary with:
        - name: Instance name
        - capacity: Compute capacity
        - status: Creation status
        - read_write_dns: DNS endpoint (when available)

    Example:
        >>> create_lakebase_instance("my-app-db", capacity="CU_2")
        {"name": "my-app-db", "capacity": "CU_2", "status": "CREATING", ...}
    """
    return _create_lakebase_instance(name=name, capacity=capacity, stopped=stopped)


@mcp.tool
def get_lakebase_instance(name: str) -> Dict[str, Any]:
    """
    Get Lakebase Provisioned instance details.

    Args:
        name: Instance name

    Returns:
        Dictionary with:
        - name: Instance name
        - state: Current state (RUNNING, STOPPED, CREATING, etc.)
        - capacity: Compute capacity (CU_1, CU_2, CU_4, CU_8)
        - read_write_dns: DNS endpoint for connections
        - stopped: Whether instance is stopped

    Example:
        >>> get_lakebase_instance("my-app-db")
        {"name": "my-app-db", "state": "RUNNING", "capacity": "CU_2", "read_write_dns": "..."}
    """
    return _get_lakebase_instance(name=name)


@mcp.tool
def list_lakebase_instances() -> List[Dict[str, Any]]:
    """
    List all Lakebase Provisioned instances in the workspace.

    Returns:
        List of instance dictionaries with name, state, capacity, and stopped status.

    Example:
        >>> list_lakebase_instances()
        [{"name": "my-app-db", "state": "RUNNING", "capacity": "CU_2", ...}]
    """
    return _list_lakebase_instances()


@mcp.tool
def update_lakebase_instance(
    name: str,
    capacity: Optional[str] = None,
    stopped: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Update a Lakebase Provisioned instance (resize or start/stop).

    Use stopped=True to stop an instance (saves cost when not in use).
    Use stopped=False to restart a stopped instance.

    Args:
        name: Instance name
        capacity: New compute capacity: "CU_1", "CU_2", "CU_4", or "CU_8"
        stopped: True to stop instance (saves cost), False to start it

    Returns:
        Dictionary with updated instance details

    Example:
        >>> update_lakebase_instance("my-app-db", stopped=True)
        {"name": "my-app-db", "status": "UPDATED", "stopped": true}

        >>> update_lakebase_instance("my-app-db", capacity="CU_4")
        {"name": "my-app-db", "status": "UPDATED", "capacity": "CU_4"}
    """
    return _update_lakebase_instance(name=name, capacity=capacity, stopped=stopped)


@mcp.tool
def delete_lakebase_instance(
    name: str,
    force: bool = False,
    purge: bool = True,
) -> Dict[str, Any]:
    """
    Delete a Lakebase Provisioned instance.

    Delete all associated catalogs, synced tables, and child instances first,
    or use force=True to delete child instances automatically.

    Args:
        name: Instance name to delete
        force: If True, delete child instances as well (default: False)
        purge: Required to be True to confirm deletion (default: True)

    Returns:
        Dictionary with name and status ("deleted" or error info)

    Example:
        >>> delete_lakebase_instance("my-app-db")
        {"name": "my-app-db", "status": "deleted"}
    """
    return _delete_lakebase_instance(name=name, force=force, purge=purge)


@mcp.tool
def generate_lakebase_credential(
    instance_names: List[str],
) -> Dict[str, Any]:
    """
    Generate an OAuth token for connecting to Lakebase instances.

    The token is valid for ~1 hour. Use it as the password in PostgreSQL
    connection strings with sslmode=require.

    Args:
        instance_names: List of instance names to generate credentials for

    Returns:
        Dictionary with:
        - token: OAuth token (use as password in connection string)
        - instance_names: Instances the token is valid for
        - message: Usage instructions

    Example:
        >>> generate_lakebase_credential(["my-app-db"])
        {"token": "eyJ...", "instance_names": ["my-app-db"], "message": "Token generated..."}
    """
    return _generate_lakebase_credential(instance_names=instance_names)


# ============================================================================
# Catalog Registration Tools
# ============================================================================


@mcp.tool
def create_lakebase_catalog(
    name: str,
    instance_name: str,
    database_name: str = "databricks_postgres",
    create_database_if_not_exists: bool = False,
) -> Dict[str, Any]:
    """
    Register a Lakebase instance as a Unity Catalog catalog.

    This makes the Lakebase PostgreSQL database discoverable and
    governable through Unity Catalog. The catalog is read-only.

    Args:
        name: Catalog name in Unity Catalog
        instance_name: Lakebase instance name to register
        database_name: PostgreSQL database name to register
            (default: "databricks_postgres")
        create_database_if_not_exists: If True, create the Postgres database
            if it does not exist (default: False)

    Returns:
        Dictionary with name, instance_name, database_name, and status

    Example:
        >>> create_lakebase_catalog("my_app_catalog", "my-app-db")
        {"name": "my_app_catalog", "instance_name": "my-app-db", ...}

        >>> create_lakebase_catalog("my_catalog", "my-instance", database_name="new_db")
        {"name": "my_catalog", "database_name": "new_db", "status": "created"}
    """
    return _create_lakebase_catalog(
        name=name,
        instance_name=instance_name,
        database_name=database_name,
        create_database_if_not_exists=create_database_if_not_exists,
    )


@mcp.tool
def get_lakebase_catalog(name: str) -> Dict[str, Any]:
    """
    Get details of a Lakebase catalog registered in Unity Catalog.

    Args:
        name: Catalog name

    Returns:
        Dictionary with catalog details including instance_name and state

    Example:
        >>> get_lakebase_catalog("my_app_catalog")
        {"name": "my_app_catalog", "instance_name": "my-app-db", ...}
    """
    return _get_lakebase_catalog(name=name)


@mcp.tool
def delete_lakebase_catalog(name: str) -> Dict[str, Any]:
    """
    Remove a Lakebase catalog registration from Unity Catalog.

    This does not delete the underlying database instance.

    Args:
        name: Catalog name to remove

    Returns:
        Dictionary with name and status ("deleted" or error info)

    Example:
        >>> delete_lakebase_catalog("my_app_catalog")
        {"name": "my_app_catalog", "status": "deleted"}
    """
    return _delete_lakebase_catalog(name=name)


# ============================================================================
# Synced Table (Reverse ETL) Tools
# ============================================================================


@mcp.tool
def create_synced_table(
    instance_name: str,
    source_table_name: str,
    target_table_name: str,
    primary_key_columns: Optional[List[str]] = None,
    scheduling_policy: str = "TRIGGERED",
) -> Dict[str, Any]:
    """
    Create a synced table to replicate data from a Delta table to Lakebase.

    Enables reverse ETL: syncing processed Lakehouse data into PostgreSQL
    for low-latency OLTP access by applications.

    Args:
        instance_name: Lakebase instance name
        source_table_name: Fully qualified source Delta table
            (catalog.schema.table_name)
        target_table_name: Fully qualified target table name
            (catalog.schema.table_name)
        primary_key_columns: List of primary key column names. If not provided,
            the source table's primary key is used.
        scheduling_policy: Sync mode: "TRIGGERED" (manual sync), "SNAPSHOT"
            (full refresh), or "CONTINUOUS" (real-time). Default: "TRIGGERED"

    Returns:
        Dictionary with instance_name, source/target table names, and status

    Example:
        >>> create_synced_table(
        ...     instance_name="my-app-db",
        ...     source_table_name="gold.products.catalog",
        ...     target_table_name="app_catalog.public.products",
        ...     primary_key_columns=["id"]
        ... )
        {"instance_name": "my-app-db", "status": "CREATING", ...}
    """
    return _create_synced_table(
        instance_name=instance_name,
        source_table_name=source_table_name,
        target_table_name=target_table_name,
        primary_key_columns=primary_key_columns,
        scheduling_policy=scheduling_policy,
    )


@mcp.tool
def get_synced_table(
    table_name: str,
) -> Dict[str, Any]:
    """
    Get status and details of a synced table.

    Args:
        table_name: Fully qualified synced table name
            (catalog.schema.table_name)

    Returns:
        Dictionary with table details including sync status

    Example:
        >>> get_synced_table("app_catalog.public.products")
        {"table_name": "app_catalog.public.products", "state": "ACTIVE", ...}
    """
    return _get_synced_table(table_name=table_name)


@mcp.tool
def delete_synced_table(
    table_name: str,
) -> Dict[str, Any]:
    """
    Delete a synced table.

    Stops syncing and removes the target table from Lakebase.
    The source Delta table is not affected.

    Args:
        table_name: Fully qualified synced table name
            (catalog.schema.table_name)

    Returns:
        Dictionary with table_name and status ("deleted" or error info)

    Example:
        >>> delete_synced_table("app_catalog.public.products")
        {"table_name": "app_catalog.public.products", "status": "deleted"}
    """
    return _delete_synced_table(table_name=table_name)
