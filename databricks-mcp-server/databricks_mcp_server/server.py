"""
Databricks MCP Server

A FastMCP server that exposes Databricks operations as MCP tools.
Simply wraps functions from databricks-mcp-core.
"""
from fastmcp import FastMCP

# Create the server
mcp = FastMCP("Databricks MCP Server")

# Import and register all tools
from .tools import sql, compute, file, pipelines

if __name__ == "__main__":
    mcp.run()
