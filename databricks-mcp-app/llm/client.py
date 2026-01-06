"""
Databricks Model Serving LLM Client

Connects to Databricks Model Serving endpoint using OpenAI-compatible API.
"""
import os
from typing import List, Optional
from openai import OpenAI
from databricks.sdk import WorkspaceClient


class DatabricksLLMClient:
    """Client for Databricks Model Serving endpoints with OpenAI-compatible API."""

    def __init__(self, endpoint_name: Optional[str] = None):
        """
        Initialize Databricks LLM client.

        Args:
            endpoint_name: Name of the Databricks Model Serving endpoint.
                          Defaults to LLM_ENDPOINT env var or 'databricks-claude-sonnet-4-5'
        """
        # Get Databricks workspace client for auth
        w = WorkspaceClient()

        # Get auth headers (handles various auth methods)
        # authenticate() returns dict like {'Authorization': 'Bearer ...'}
        auth_headers = w.config.authenticate()
        if not auth_headers or 'Authorization' not in auth_headers:
            raise ValueError(
                "Unable to get Databricks auth token. "
                "Please configure authentication."
            )

        # Extract token from Authorization header (remove 'Bearer ' prefix)
        auth_header = auth_headers['Authorization']
        token = auth_header.replace('Bearer ', '')

        # Configure OpenAI client with Databricks endpoint
        self.client = OpenAI(
            api_key=token,
            base_url=f"{w.config.host}/serving-endpoints"
        )

        # Set model/endpoint name
        self.model = endpoint_name or os.getenv(
            "LLM_ENDPOINT",
            "databricks-claude-sonnet-4-5"
        )

    def chat(
        self,
        messages: List[dict],
        tools: Optional[List[dict]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> dict:
        """
        Send chat completion request to Databricks Model Serving endpoint.

        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions in OpenAI format
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate

        Returns:
            OpenAI chat completion response
        """
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        if tools:
            kwargs["tools"] = tools
            # Let model decide when to use tools vs respond
            kwargs["tool_choice"] = "auto"

        return self.client.chat.completions.create(**kwargs)
