#!/bin/bash
cd "$(dirname "$0")"

echo "Starting Databricks MCP App..."
echo "================================"
echo ""
echo "App will be available at: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop"
echo ""

uvicorn app:app --host 0.0.0.0 --port 8080
