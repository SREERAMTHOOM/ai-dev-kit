"""
Table Statistics

High-level function for getting table details and statistics.
"""

import logging
from typing import List, Optional

from .sql_utils.models import TableSchemaResult, TableStatLevel
from .sql_utils.table_stats_collector import TableStatsCollector
from .warehouse import get_best_warehouse

logger = logging.getLogger(__name__)


def _has_glob_pattern(name: str) -> bool:
    """Check if a name contains glob pattern characters."""
    return any(c in name for c in ["*", "?", "[", "]"])


def get_table_details(
    catalog: str,
    schema: str,
    table_names: Optional[List[str]] = None,
    table_stat_level: TableStatLevel = TableStatLevel.SIMPLE,
    warehouse_id: Optional[str] = None,
) -> TableSchemaResult:
    """
    Get detailed information about tables in a schema.

    Supports three modes based on table_names:
    1. Empty list or None: List all tables in the schema
    2. Names with glob patterns (*, ?, []): List tables and filter by pattern
    3. Exact names: Get tables directly without listing (faster)

    Args:
        catalog: Catalog name
        schema: Schema name
        table_names: Optional list of table names or glob patterns.
            Examples:
            - None or []: Get all tables
            - ["customers", "orders"]: Get specific tables
            - ["raw_*"]: Get all tables starting with "raw_"
            - ["*_customers", "orders"]: Mix of patterns and exact names
        table_stat_level: Level of statistics to collect:
            - NONE: Just DDL, no stats (fast, no cache)
            - SIMPLE: Basic stats with caching (default)
            - DETAILED: Full stats including histograms, percentiles
        warehouse_id: Optional warehouse ID. If not provided, auto-selects one.

    Returns:
        TableSchemaResult containing table information with requested stat level

    Raises:
        Exception: If warehouse not available or catalog/schema doesn't exist

    Examples:
        >>> # Get all tables with basic stats
        >>> result = get_table_details("my_catalog", "my_schema")

        >>> # Get specific tables
        >>> result = get_table_details("my_catalog", "my_schema", ["customers", "orders"])

        >>> # Get tables matching pattern with full stats
        >>> result = get_table_details(
        ...     "my_catalog", "my_schema",
        ...     ["gold_*"],
        ...     table_stat_level=TableStatLevel.DETAILED
        ... )

        >>> # Quick DDL-only lookup (no stats)
        >>> result = get_table_details(
        ...     "my_catalog", "my_schema",
        ...     ["my_table"],
        ...     table_stat_level=TableStatLevel.NONE
        ... )
    """
    # Auto-select warehouse if not provided
    if not warehouse_id:
        logger.debug("No warehouse_id provided, selecting best available warehouse")
        warehouse_id = get_best_warehouse()
        if not warehouse_id:
            raise Exception(
                "No SQL warehouse available in the workspace. "
                "Please create a SQL warehouse or start an existing one, "
                "or provide a specific warehouse_id."
            )
        logger.debug(f"Auto-selected warehouse: {warehouse_id}")

    collector = TableStatsCollector(warehouse_id=warehouse_id)

    # Determine if we need to list tables
    table_names = table_names or []
    has_patterns = any(_has_glob_pattern(name) for name in table_names)
    needs_listing = len(table_names) == 0 or has_patterns

    if needs_listing:
        # List all tables first
        logger.debug(f"Listing tables in {catalog}.{schema}")
        all_tables = collector.list_tables(catalog, schema)

        if table_names:
            # Filter by patterns
            tables_to_fetch = collector.filter_tables_by_patterns(all_tables, table_names)
            logger.debug(
                f"Filtered {len(all_tables)} tables to {len(tables_to_fetch)} "
                f"matching patterns: {table_names}"
            )
        else:
            tables_to_fetch = all_tables
            logger.debug(f"Found {len(tables_to_fetch)} tables")
    else:
        # Direct lookup - build table info without listing
        logger.debug(f"Direct lookup for tables: {table_names}")
        tables_to_fetch = [{"name": name, "updated_at": None, "comment": None} for name in table_names]

    if not tables_to_fetch:
        return TableSchemaResult(catalog=catalog, schema_name=schema, tables=[])

    # Determine whether to collect stats
    collect_stats = table_stat_level != TableStatLevel.NONE

    # Fetch table info (with or without stats)
    logger.info(
        f"Fetching {len(tables_to_fetch)} tables with stat_level={table_stat_level.value}"
    )
    table_infos = collector.get_tables_info_parallel(
        catalog=catalog,
        schema=schema,
        tables=tables_to_fetch,
        collect_stats=collect_stats,
    )

    # Build result
    result = TableSchemaResult(
        catalog=catalog,
        schema_name=schema,
        tables=table_infos,
    )

    # Apply stat level transformation
    if table_stat_level == TableStatLevel.SIMPLE:
        return result.keep_basic_stats()
    elif table_stat_level == TableStatLevel.NONE:
        return result.remove_stats()
    else:
        # DETAILED - return everything
        return result
