"""
Compute - Execution Context Operations

Functions for executing code on Databricks clusters using execution contexts.
Uses Databricks Command Execution API via SDK.
"""
import datetime
from typing import Optional
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.compute import Language


class ExecutionResult:
    """Result from code execution"""

    def __init__(
        self,
        success: bool,
        output: Optional[str] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.output = output
        self.error = error

    def __repr__(self):
        if self.success:
            return (
                f"ExecutionResult(success=True, output={repr(self.output)})"
            )
        return f"ExecutionResult(success=False, error={repr(self.error)})"


def create_context(cluster_id: str, language: str = "python") -> str:
    """
    Create a new execution context on a Databricks cluster.

    Args:
        cluster_id: ID of the cluster to create context on
        language: Programming language ("python", "scala", "sql", "r")

    Returns:
        Context ID string

    Raises:
        DatabricksError: If API request fails
    """
    w = WorkspaceClient()

    # Convert string to Language enum
    lang_map = {
        "python": Language.PYTHON,
        "scala": Language.SCALA,
        "sql": Language.SQL,
        "r": Language.R
    }
    lang_enum = lang_map.get(language.lower(), Language.PYTHON)

    # SDK returns Wait object, need to wait for result
    result = w.command_execution.create(
        cluster_id=cluster_id,
        language=lang_enum
    ).result()  # Blocks until context is created

    return result.id


def execute_command_with_context(
    cluster_id: str,
    context_id: str,
    code: str,
    timeout: int = 120
) -> ExecutionResult:
    """
    Execute code using an existing execution context.

    Maintains state between calls.

    Args:
        cluster_id: ID of the cluster
        context_id: ID of the execution context
        code: Code to execute
        timeout: Maximum time to wait for execution (seconds)

    Returns:
        ExecutionResult with output or error

    Raises:
        DatabricksError: If API request fails
        TimeoutError: If execution exceeds timeout
    """
    w = WorkspaceClient()

    try:
        # Execute and wait for result with timeout
        result = w.command_execution.execute(
            cluster_id=cluster_id,
            context_id=context_id,
            language=Language.PYTHON,
            command=code
        ).result(timeout=datetime.timedelta(seconds=timeout))

        # Check result status
        if result.status == "Finished":
            output = (
                result.results.data if result.results
                else "Success (no output)"
            )
            return ExecutionResult(success=True, output=str(output))
        elif result.status in ["Error", "Cancelled"]:
            error_msg = (
                result.results.cause if result.results
                else "Unknown error"
            )
            return ExecutionResult(success=False, error=error_msg)
        else:
            return ExecutionResult(
                success=False,
                error=f"Unexpected status: {result.status}"
            )

    except TimeoutError:
        return ExecutionResult(success=False, error="Command timed out")


def destroy_context(cluster_id: str, context_id: str) -> None:
    """
    Destroy an execution context.

    Args:
        cluster_id: ID of the cluster
        context_id: ID of the context to destroy

    Raises:
        DatabricksError: If API request fails
    """
    w = WorkspaceClient()
    w.command_execution.destroy(
        cluster_id=cluster_id,
        context_id=context_id
    )


def execute_databricks_command(
    cluster_id: str,
    language: str,
    code: str,
    timeout: int = 120
) -> ExecutionResult:
    """
    Execute code on Databricks cluster.

    Creates and destroys context automatically.

    This is a convenience function for one-off command execution. For multiple
    commands that need to maintain state, use create_context() and
    execute_command_with_context() explicitly.

    Args:
        cluster_id: ID of the cluster
        language: Programming language ("python", "scala", "sql", "r")
        code: Code to execute
        timeout: Maximum time to wait for execution (seconds)

    Returns:
        ExecutionResult with output or error

    Raises:
        DatabricksError: If API request fails
    """
    # Create context
    context_id = create_context(cluster_id, language)

    try:
        # Execute command
        return execute_command_with_context(
            cluster_id=cluster_id,
            context_id=context_id,
            code=code,
            timeout=timeout
        )
    finally:
        # Always clean up context
        try:
            destroy_context(cluster_id, context_id)
        except Exception:
            pass  # Ignore cleanup errors


def run_python_file_on_databricks(
    cluster_id: str,
    file_path: str,
    timeout: int = 600
) -> ExecutionResult:
    """
    Read a local Python file and execute it on a Databricks cluster.

    This is useful for running data generation scripts or other Python code
    that has been written locally and needs to be executed on Databricks.

    Args:
        cluster_id: ID of the cluster to run the code on
        file_path: Local path to the Python file to execute
        timeout: Maximum time to wait for execution (seconds, default 600)

    Returns:
        ExecutionResult with output or error

    Raises:
        FileNotFoundError: If the file doesn't exist
        DatabricksError: If API request fails

    Example:
        >>> result = run_python_file_on_databricks(
        ...     cluster_id="0123-456789-abcde",
        ...     file_path="/path/to/generate_data.py"
        ... )
        >>> if result.success:
        ...     print(result.output)
        ... else:
        ...     print(f"Error: {result.error}")
    """
    # Read the file contents
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        return ExecutionResult(
            success=False,
            error=f"File not found: {file_path}"
        )
    except Exception as e:
        return ExecutionResult(
            success=False,
            error=f"Failed to read file {file_path}: {str(e)}"
        )

    if not code.strip():
        return ExecutionResult(
            success=False,
            error=f"File is empty: {file_path}"
        )

    # Execute the code on Databricks
    return execute_databricks_command(
        cluster_id=cluster_id,
        language="python",
        code=code,
        timeout=timeout
    )
