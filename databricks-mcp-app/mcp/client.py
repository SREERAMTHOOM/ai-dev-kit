"""
MCP stdio Client

Communicates with databricks-mcp-server via stdio subprocess using JSON-RPC 2.0.
"""
import json
import subprocess
import threading
import uuid
from typing import Dict, Any, List, Optional
from queue import Queue, Empty
import logging

logger = logging.getLogger(__name__)


class MCPStdioClient:
    """Client for communicating with MCP server via stdio subprocess."""

    def __init__(self, server_command: Optional[List[str]] = None):
        """
        Initialize MCP stdio client.

        Args:
            server_command: Command to start MCP server.
                          Defaults to ["python", "-m", "databricks_mcp_server.stdio_server"]
        """
        if server_command is None:
            server_command = ["python", "-m", "databricks_mcp_server.stdio_server"]

        self.server_command = server_command
        self.process: Optional[subprocess.Popen] = None
        self.response_queue: Queue = Queue()
        self.pending_requests: Dict[str, Queue] = {}
        self.reader_thread: Optional[threading.Thread] = None
        self.initialized = False

    def start(self):
        """Start the MCP server subprocess and reader thread."""
        if self.process is not None:
            logger.warning("MCP server already running")
            return

        logger.info(f"Starting MCP server: {' '.join(self.server_command)}")

        # Start subprocess with pipes for stdin/stdout
        # stderr is logged separately for debugging
        self.process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            env=None  # Inherit parent environment (includes .env variables)
        )

        # Start reader thread to handle responses
        self.reader_thread = threading.Thread(
            target=self._read_responses, daemon=True
        )
        self.reader_thread.start()

        # Start stderr reader thread for error logging
        self.stderr_thread = threading.Thread(
            target=self._read_stderr, daemon=True
        )
        self.stderr_thread.start()

        logger.info(f"MCP server started with PID: {self.process.pid}")

    def stop(self):
        """Stop the MCP server subprocess."""
        if self.process is None:
            return

        logger.info("Stopping MCP server")

        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("MCP server did not terminate gracefully, killing")
            self.process.kill()
            self.process.wait()

        self.process = None
        self.initialized = False
        logger.info("MCP server stopped")

    def _read_responses(self):
        """Background thread to read responses from server stdout."""
        if self.process is None or self.process.stdout is None:
            return

        try:
            for line in self.process.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    response = json.loads(line)
                    request_id = response.get("id")

                    if request_id and request_id in self.pending_requests:
                        # Put response in the specific request's queue
                        self.pending_requests[request_id].put(response)
                    else:
                        # Unexpected response
                        logger.warning(
                            f"Received response for unknown request ID: "
                            f"{request_id}"
                        )

                except json.JSONDecodeError as e:
                    logger.error(
                        f"Failed to parse JSON response: {e}, line: {line}"
                    )

        except Exception as e:
            logger.error(f"Error in response reader thread: {e}")

    def _read_stderr(self):
        """Background thread to read and log stderr from server."""
        if self.process is None or self.process.stderr is None:
            return

        try:
            for line in self.process.stderr:
                line = line.strip()
                if line:
                    # Log stderr from MCP server for debugging
                    logger.warning(f"MCP server stderr: {line}")
        except Exception as e:
            logger.error(f"Error in stderr reader thread: {e}")

    def _send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send JSON-RPC request to server and wait for response.

        Args:
            method: JSON-RPC method name
            params: Optional method parameters

        Returns:
            JSON-RPC response result

        Raises:
            RuntimeError: If server not started or request fails
        """
        if self.process is None or self.process.stdin is None:
            raise RuntimeError("MCP server not started. Call start() first.")

        # Generate unique request ID
        request_id = str(uuid.uuid4())

        # Build JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method
        }
        if params is not None:
            request["params"] = params

        # Create queue for this request's response
        response_queue: Queue = Queue()
        self.pending_requests[request_id] = response_queue

        try:
            # Send request
            request_line = json.dumps(request, ensure_ascii=False) + "\n"
            self.process.stdin.write(request_line)
            self.process.stdin.flush()

            logger.debug(f"Sent request: {method} (id: {request_id})")

            # Wait for response (with timeout)
            try:
                response = response_queue.get(timeout=30.0)
            except Empty:
                raise RuntimeError(f"Request timeout: {method}")

            # Check for JSON-RPC error
            if "error" in response:
                error = response["error"]
                raise RuntimeError(f"MCP server error: {error.get('message', 'Unknown error')}")

            # Return result
            return response.get("result", {})

        finally:
            # Clean up request queue
            if request_id in self.pending_requests:
                del self.pending_requests[request_id]

    def initialize(self) -> Dict[str, Any]:
        """
        Initialize MCP server and get capabilities.

        Returns:
            Server initialization result with capabilities and serverInfo
        """
        if self.initialized:
            logger.warning("MCP server already initialized")
            return {}

        result = self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "databricks-mcp-app",
                    "version": "1.0.0"
                }
            }
        )

        self.initialized = True
        logger.info(f"MCP server initialized: {result.get('serverInfo', {})}")
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        """
        Get list of available tools from server.

        Returns:
            List of MCP tool definitions
        """
        if not self.initialized:
            raise RuntimeError("Server not initialized. Call initialize() first.")

        result = self._send_request("tools/list")
        tools = result.get("tools", [])
        logger.info(f"Loaded {len(tools)} tools from MCP server")
        return tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool on the MCP server.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool execution result in MCP format:
            {
                "content": [{"type": "text", "text": "..."}],
                "isError": false
            }
        """
        if not self.initialized:
            raise RuntimeError("Server not initialized. Call initialize() first.")

        logger.debug(f"Calling tool: {name} with args: {arguments}")

        result = self._send_request(
            "tools/call",
            {
                "name": name,
                "arguments": arguments
            }
        )

        return result

    def __enter__(self):
        """Context manager entry."""
        self.start()
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
