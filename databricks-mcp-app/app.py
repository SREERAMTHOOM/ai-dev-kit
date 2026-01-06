"""
Databricks Natural Language Builder App

FastAPI application that allows users to create Databricks resources
through natural language chat using Databricks Model Serving endpoints.
"""
import os
import uuid
from typing import Dict, List, Optional
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import json as json_module

from llm.client import DatabricksLLMClient
from llm.orchestrator import ToolOrchestrator


# Initialize FastAPI app
app = FastAPI(
    title="Databricks Natural Language Builder",
    description="Create Databricks resources using natural language",
    version="1.0.0"
)

# Add CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (use Redis/DB for production)
sessions: Dict[str, Dict] = {}

# Tool execution event queues for SSE streaming
tool_events: Dict[str, asyncio.Queue] = {}


# Request/Response Models
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    timestamp: str
    error: bool = False
    tools_used: List[Dict] = []


class SessionInfo(BaseModel):
    session_id: str
    created_at: str
    message_count: int


# Initialize LLM orchestrator
orchestrator: Optional[ToolOrchestrator] = None


@app.on_event("startup")
async def startup_event():
    """Initialize LLM client on startup."""
    global orchestrator
    try:
        llm_endpoint = os.getenv("LLM_ENDPOINT", "databricks-claude-sonnet-4-5")
        llm_client = DatabricksLLMClient(endpoint_name=llm_endpoint)
        orchestrator = ToolOrchestrator(llm_client)
        print(f"✅ LLM client initialized with endpoint: {llm_endpoint}")
    except Exception as e:
        print(f"⚠️  Warning: Failed to initialize LLM client: {e}")
        print("    The app will start but chat functionality will be unavailable.")


# API Endpoints

@app.get("/api/chat/stream/{session_id}")
async def chat_stream(session_id: str):
    """Stream tool execution events via Server-Sent Events."""
    async def event_generator():
        # Create queue for this session if it doesn't exist
        if session_id not in tool_events:
            tool_events[session_id] = asyncio.Queue()

        queue = tool_events[session_id]

        try:
            while True:
                # Wait for events with timeout
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json_module.dumps(event)}\n\n"

                    # If this is a 'done' event, stop streaming
                    if event.get('type') == 'done':
                        break
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield f": keepalive\n\n"
        finally:
            # Clean up queue
            if session_id in tool_events:
                del tool_events[session_id]

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Handle chat messages with session management.

    Creates new session if session_id not provided.
    Maintains conversation history per session.
    """
    if orchestrator is None:
        raise HTTPException(
            status_code=503,
            detail="LLM client not initialized. Check server logs for details."
        )

    try:
        # Get or create session
        session_id = request.session_id or str(uuid.uuid4())

        if session_id not in sessions:
            sessions[session_id] = {
                "id": session_id,
                "created_at": datetime.utcnow().isoformat(),
                "history": [],
                "message_count": 0
            }

        session = sessions[session_id]

        # Create event queue for this session
        if session_id not in tool_events:
            tool_events[session_id] = asyncio.Queue()

        # Emit start event
        await tool_events[session_id].put({
            "type": "start",
            "status": "Processing request..."
        })

        # Define callback for tool execution events
        def tool_callback(event):
            # Put event in queue (non-async, called from sync code)
            asyncio.create_task(tool_events[session_id].put(event))

        # Process message with orchestrator
        result = orchestrator.process_message(
            request.message,
            session["history"],
            tool_callback=tool_callback
        )

        # Emit done event
        await tool_events[session_id].put({
            "type": "done",
            "tools_used": result.get("tools_used", [])
        })

        # Update session
        session["history"] = result["history"]
        session["message_count"] += 1

        return ChatResponse(
            response=result["response"],
            session_id=session_id,
            timestamp=datetime.utcnow().isoformat(),
            error=result.get("error", False),
            tools_used=result.get("tools_used", [])
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Chat processing failed: {str(e)}"
        )


@app.get("/api/sessions/{session_id}", response_model=SessionInfo)
async def get_session(session_id: str):
    """Get session information."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = sessions[session_id]
    return SessionInfo(
        session_id=session["id"],
        created_at=session["created_at"],
        message_count=session["message_count"]
    )


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and its history."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    del sessions[session_id]
    return {"message": "Session deleted successfully"}


@app.get("/api/sessions")
async def list_sessions():
    """List all active sessions."""
    return {
        "sessions": [
            {
                "session_id": s["id"],
                "created_at": s["created_at"],
                "message_count": s["message_count"]
            }
            for s in sessions.values()
        ]
    }


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "llm_initialized": orchestrator is not None,
        "active_sessions": len(sessions),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/tools")
async def list_tools():
    """List available tools grouped by category."""
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="LLM client not initialized")

    try:
        orchestrator._load_tools()

        # Group tools by category
        unity_catalog = []
        pipelines = []
        synthetic_data = []
        compute = []

        for tool in orchestrator.tools:
            name = tool["function"]["name"]
            desc = tool["function"]["description"]

            if any(x in name for x in ["catalog", "schema", "table"]):
                unity_catalog.append({"name": name, "description": desc})
            elif any(x in name for x in ["pipeline", "sdp", "file", "directory"]):
                pipelines.append({"name": name, "description": desc})
            elif "synth" in name:
                synthetic_data.append({"name": name, "description": desc})
            elif any(x in name for x in ["context", "command", "execute"]):
                compute.append({"name": name, "description": desc})

        categories = []
        if unity_catalog:
            categories.append({
                "category": "Unity Catalog",
                "description": "Create and manage catalogs, schemas, and tables",
                "tools": unity_catalog
            })
        if pipelines:
            categories.append({
                "category": "Spark Declarative Pipelines",
                "description": "Create and manage data pipelines",
                "tools": pipelines
            })
        if synthetic_data:
            categories.append({
                "category": "Synthetic Data Generation",
                "description": "Generate and upload test data",
                "tools": synthetic_data
            })
        if compute:
            categories.append({
                "category": "Compute Operations",
                "description": "Execute code and manage compute contexts",
                "tools": compute
            })

        return {"toolCategories": categories}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Serve static files (frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def root():
    """Serve chat UI."""
    return FileResponse("static/index.html")


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__
        }
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("DATABRICKS_APP_PORT", "8080"))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
