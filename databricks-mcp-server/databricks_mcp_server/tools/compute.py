"""Compute tools - Execute code on Databricks clusters."""
from typing import Dict, Any

from databricks_mcp_core.compute import (
    execute_databricks_command as _execute_databricks_command,
    run_python_file_on_databricks as _run_python_file_on_databricks,
)

from ..server import mcp


@mcp.tool
def execute_databricks_command(
    cluster_id: str,
    language: str,
    code: str,
    timeout: int = 120,
) -> Dict[str, Any]:
    """
    Execute code on a Databricks cluster.

    Creates an execution context, runs the code, and cleans up automatically.

    Args:
        cluster_id: ID of the cluster to run on
        language: Programming language ("python", "scala", "sql", "r")
        code: Code to execute
        timeout: Maximum wait time in seconds (default: 120)

    Returns:
        Dictionary with success status and output or error message.
    """
    result = _execute_databricks_command(
        cluster_id=cluster_id,
        language=language,
        code=code,
        timeout=timeout,
    )
    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
    }


@mcp.tool
def run_python_file_on_databricks(
    cluster_id: str,
    file_path: str,
    timeout: int = 600,
) -> Dict[str, Any]:
    """
    Read a local Python file and execute it on a Databricks cluster.

    Useful for running data generation scripts or other Python code.

    Args:
        cluster_id: ID of the cluster to run on
        file_path: Local path to the Python file
        timeout: Maximum wait time in seconds (default: 600)

    Returns:
        Dictionary with success status and output or error message.
    """
    result = _run_python_file_on_databricks(
        cluster_id=cluster_id,
        file_path=file_path,
        timeout=timeout,
    )
    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
    }
