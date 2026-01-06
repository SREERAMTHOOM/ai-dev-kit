"""
LLM Orchestrator

Coordinates LLM chat with tool execution loop for Databricks resource creation.
"""
import json
import os
from typing import List, Dict, Any, Optional
from .client import DatabricksLLMClient
from mcp.client import MCPStdioClient


class ToolOrchestrator:
    """Orchestrates LLM conversation with tool calling."""

    def __init__(self, llm_client: DatabricksLLMClient):
        """
        Initialize orchestrator.

        Args:
            llm_client: Configured Databricks LLM client
        """
        self.llm = llm_client
        self.tools = None
        self.mcp_client: Optional[MCPStdioClient] = None
        self.system_prompt = self._build_system_prompt()

        # Lazy load tools to avoid import issues at startup
        self._tools_loaded = False

    def _load_tools(self):
        """Lazy load tools from MCP server via stdio."""
        if not self._tools_loaded:
            # Start MCP server subprocess
            cmd = os.getenv(
                "MCP_SERVER_COMMAND",
                "python -m databricks_mcp_server.stdio_server"
            ).split()
            self.mcp_client = MCPStdioClient(cmd)
            self.mcp_client.start()
            self.mcp_client.initialize()

            # Get tools in MCP format and convert to OpenAI format
            mcp_tools = self.mcp_client.list_tools()
            self.tools = self._convert_mcp_to_openai_format(mcp_tools)
            self._tools_loaded = True

    def _convert_mcp_to_openai_format(
        self, mcp_tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert MCP tool definitions to OpenAI function calling format.

        Args:
            mcp_tools: List of MCP tool definitions

        Returns:
            List of OpenAI-formatted tool definitions
        """
        openai_tools = []
        for tool in mcp_tools:
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {})
                }
            }
            openai_tools.append(openai_tool)
        return openai_tools

    def _build_system_prompt(self) -> str:
        """Build system prompt to guide LLM behavior."""
        return """You are a Databricks resource builder assistant with DIRECT execution capabilities.

CRITICAL RULES - YOU MUST FOLLOW THESE:
1. You have tools that DIRECTLY create/manage resources - USE THEM, DO NOT provide SQL
2. NEVER respond with SQL statements like "CREATE TABLE..." or "CREATE SCHEMA..."
3. NEVER tell users to run commands themselves
4. YOU execute the operations directly using your tools

CORRECT behavior example:
User: "Create a table called users with columns id, name, email"
Assistant: [CALLS create_table tool directly]
Assistant: "✓ Successfully created table main.default.users with columns: id (INT), name (STRING), email (STRING)"

WRONG behavior (NEVER do this):
User: "Create a table called users"
Assistant: "Here's the SQL: CREATE TABLE users..." ❌ WRONG - This violates the rules

YOU MUST USE THESE TOOLS:
- create_table: Creates tables directly in Unity Catalog
- create_schema: Creates schemas directly in Unity Catalog
- list_catalogs, list_schemas, list_tables: Browse existing resources
- create_pipeline: Creates Spark pipelines
- generate_and_upload_synth_data: Generates synthetic data

MANDATORY WORKFLOW:
1. User asks to create something → YOU call the create tool immediately
2. Tool returns result → YOU report success/failure to user
3. NEVER skip step 1 and provide SQL instead

If a tool fails, report the error and suggest fixes. But ALWAYS attempt to use tools first.
"""

    def process_message(
        self,
        user_message: str,
        history: Optional[List[Dict[str, Any]]] = None,
        tool_callback=None
    ) -> Dict[str, Any]:
        """
        Process user message with tool calling loop.

        Args:
            user_message: User's input message
            history: Optional conversation history (excludes system prompt)

        Returns:
            Dict with 'response' (str) and 'history' (list) keys
        """
        # Lazy load tools
        self._load_tools()

        if history is None:
            history = []

        # Build messages list with system prompt
        messages = [{"role": "system", "content": self.system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": user_message})

        # Track tool usage for explainability
        tools_used = []

        # Tool calling loop
        max_iterations = 15
        for i in range(max_iterations):
            try:
                print(f"🔄 Iteration {i+1}: Sending {len(messages)} messages with {len(self.tools) if self.tools else 0} tools")
                response = self.llm.chat(messages, tools=self.tools)
                choice = response.choices[0]
                print(f"📥 Response finish_reason: {choice.finish_reason}, has_tool_calls: {hasattr(choice.message, 'tool_calls') and choice.message.tool_calls is not None}")

                # Check if LLM wants to call tools
                has_tool_calls = getattr(choice.message, "tool_calls", None)
                if has_tool_calls:
                    # Manually construct assistant message with tool calls
                    # to ensure proper formatting for Claude
                    assistant_msg = {
                        "role": "assistant",
                        "content": choice.message.content if choice.message.content else None
                    }

                    # Add tool_calls array
                    tool_calls_list = []
                    for tc in choice.message.tool_calls:
                        tool_calls_list.append({
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        })
                    assistant_msg["tool_calls"] = tool_calls_list
                    messages.append(assistant_msg)

                    # Execute each tool call and add results one by one
                    # Claude requires each tool result to immediately follow
                    for tool_call in choice.message.tool_calls:
                        tool_name = tool_call.function.name
                        print(f"🔧 Executing tool: {tool_name} with args: {tool_call.function.arguments[:100]}...")

                        # Notify callback about tool execution
                        if tool_callback:
                            tool_callback({
                                "type": "tool_start",
                                "tool": tool_name
                            })

                        # Track tool usage for explainability
                        import json as json_lib
                        try:
                            args = json_lib.loads(tool_call.function.arguments)
                        except Exception:
                            args = {}
                        tools_used.append({
                            "name": tool_name,
                            "arguments": args
                        })

                        result = self._execute_tool(tool_call)
                        print(f"✅ Tool result: {str(result)[:200]}...")

                        # Format tool result for the model
                        # Extract just the text content for cleaner responses
                        if isinstance(result, dict) and "result" in result:
                            content = result["result"]
                        else:
                            content = json.dumps(result)

                        # Add tool result message
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": content
                        })
                else:
                    # LLM has final answer
                    return {
                        "response": choice.message.content,
                        "history": messages[1:],  # Exclude system prompt
                        "tools_used": tools_used
                    }

            except Exception as e:
                # Return error but preserve conversation
                return {
                    "response": f"Error during processing: {str(e)}",
                    "history": messages[1:],
                    "tools_used": tools_used,
                    "error": True
                }

        # Max iterations reached
        return {
            "response": "I've reached the maximum number of steps for this request. Please try rephrasing or breaking down your request.",
            "history": messages[1:],
            "tools_used": tools_used
        }

    def _execute_tool(self, tool_call) -> Dict[str, Any]:
        """
        Execute a single tool call via MCP client.

        Args:
            tool_call: OpenAI tool call object

        Returns:
            Dict with execution result or error
        """
        try:
            tool_name = tool_call.function.name
            arguments = json.loads(tool_call.function.arguments)

            if self.mcp_client is None:
                return {
                    "success": False,
                    "error": "MCP client not initialized"
                }

            # Call tool via MCP client
            result = self.mcp_client.call_tool(tool_name, arguments)

            # Extract text content from MCP response format
            # MCP returns: {"content": [{"type": "text", "text": "..."}]}
            if isinstance(result, dict) and "content" in result:
                content = result["content"]
                if isinstance(content, list) and len(content) > 0:
                    text = content[0].get("text", "")
                    is_error = result.get("isError", False)
                    return {
                        "success": not is_error,
                        "result": text,
                        "error": text if is_error else None
                    }

            # Fallback for unexpected format
            return {
                "success": True,
                "result": str(result)
            }

        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid tool arguments: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }
