# Databricks Builder App

A web application that provides a Claude Code agent interface with integrated Databricks tools. Users interact with Claude through a chat interface, and the agent can execute SQL queries, manage pipelines, upload files, and more on their Databricks workspace.

> **✅ Event Loop Fix Implemented**
>
> We've implemented a workaround for `claude-agent-sdk` [issue #462](https://github.com/anthropics/claude-agent-sdk-python/issues/462) that was preventing the agent from executing Databricks tools in FastAPI contexts.
>
> **Solution:** The agent now runs in a fresh event loop in a separate thread, with `contextvars` properly copied to preserve Databricks authentication. See [EVENT_LOOP_FIX.md](./EVENT_LOOP_FIX.md) for details.
>
> **Status:** ✅ Fully functional - agent can execute all Databricks tools successfully

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Web Application                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  React Frontend (client/)           FastAPI Backend (server/)               │
│  ┌─────────────────────┐            ┌─────────────────────────────────┐     │
│  │ Chat UI             │◄──────────►│ /api/agent/invoke               │     │
│  │ Project Selector    │   SSE      │ /api/projects                   │     │
│  │ Conversation List   │            │ /api/conversations              │     │
│  └─────────────────────┘            └─────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Claude Code Session                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Each user message spawns a Claude Code agent session via claude-agent-sdk  │
│                                                                              │
│  Built-in Tools:              MCP Tools (Databricks):         Skills:       │
│  ┌──────────────────┐         ┌─────────────────────────┐    ┌───────────┐  │
│  │ Read, Write, Edit│         │ execute_sql             │    │ sdp       │  │
│  │ Bash, Glob, Grep │         │ create_or_update_pipeline    │ dabs      │  │
│  │ Skill            │         │ upload_folder           │    │ sdk       │  │
│  └──────────────────┘         │ run_python_file         │    │ ...       │  │
│                               │ ...                     │    └───────────┘  │
│                               └─────────────────────────┘                   │
│                                          │                                  │
│                                          ▼                                  │
│                               ┌─────────────────────────┐                   │
│                               │ databricks-mcp-server   │                   │
│                               │ (stdio subprocess)      │                   │
│                               └─────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Databricks Workspace                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  SQL Warehouses    │    Clusters    │    Unity Catalog    │    Workspace    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## How It Works

### 1. Claude Code Sessions

When a user sends a message, the backend creates a Claude Code session using the `claude-agent-sdk`:

```python
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    cwd=str(project_dir),           # Project working directory
    allowed_tools=allowed_tools,     # Built-in + MCP tools
    permission_mode='acceptEdits',   # Auto-accept file edits
    resume=session_id,               # Resume previous conversation
    mcp_servers=mcp_servers,         # Databricks MCP server config
    system_prompt=system_prompt,     # Databricks-focused prompt
    setting_sources=['project'],     # Load skills from .claude/skills
)

async for msg in query(prompt=message, options=options):
    yield msg  # Stream to frontend
```

Key features:
- **Session Resumption**: Each conversation stores a `claude_session_id` for context continuity
- **Streaming**: All events (text, thinking, tool_use, tool_result) stream to the frontend in real-time
- **Project Isolation**: Each project has its own working directory with sandboxed file access

### 2. Authentication Flow

The app supports multi-user authentication using per-request credentials:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Authentication Flow                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Production (Databricks Apps)         Development (Local)                   │
│  ┌──────────────────────────┐         ┌──────────────────────────┐          │
│  │ Request Headers:         │         │ Environment Variables:   │          │
│  │ X-Forwarded-User         │         │ DATABRICKS_HOST          │          │
│  │ X-Forwarded-Access-Token │         │ DATABRICKS_TOKEN         │          │
│  └────────────┬─────────────┘         └────────────┬─────────────┘          │
│               │                                    │                        │
│               └──────────────┬─────────────────────┘                        │
│                              ▼                                              │
│               ┌──────────────────────────┐                                  │
│               │ set_databricks_auth()    │  (contextvars)                   │
│               │ - host                   │                                  │
│               │ - token                  │                                  │
│               └────────────┬─────────────┘                                  │
│                            ▼                                                │
│               ┌──────────────────────────┐                                  │
│               │ get_workspace_client()   │  (used by all tools)             │
│               │ - Returns client with    │                                  │
│               │   context credentials    │                                  │
│               └──────────────────────────┘                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**How it works:**

1. **Request arrives** - The FastAPI backend extracts credentials:
   - **Production**: `X-Forwarded-User` and `X-Forwarded-Access-Token` headers (set by Databricks Apps proxy)
   - **Development**: Falls back to `DATABRICKS_HOST` and `DATABRICKS_TOKEN` env vars

2. **Auth context set** - Before invoking the agent:
   ```python
   from databricks_tools_core.auth import set_databricks_auth, clear_databricks_auth

   set_databricks_auth(workspace_url, user_token)
   try:
       # All tool calls use this user's credentials
       async for event in stream_agent_response(...):
           yield event
   finally:
       clear_databricks_auth()
   ```

3. **Tools use context** - All Databricks tools call `get_workspace_client()` which:
   - First checks contextvars for per-request credentials
   - Falls back to environment variables if no context set

This ensures each user's requests use their own Databricks credentials, enabling proper access control and audit logging.

### 3. MCP Integration (Databricks Tools)

Databricks tools are loaded in-process using the Claude Agent SDK's MCP server feature:

```python
from claude_agent_sdk import tool, create_sdk_mcp_server

# Tools are dynamically loaded from databricks-mcp-server
server = create_sdk_mcp_server(name='databricks', tools=sdk_tools)

options = ClaudeAgentOptions(
    mcp_servers={'databricks': server},
    allowed_tools=['mcp__databricks__execute_sql', ...],
)
```

Tools are exposed as `mcp__databricks__<tool_name>` and include:
- SQL execution (`execute_sql`, `execute_sql_multi`)
- Warehouse management (`list_warehouses`, `get_best_warehouse`)
- Cluster execution (`execute_databricks_command`, `run_python_file_on_databricks`)
- Pipeline management (`create_or_update_pipeline`, `start_update`, etc.)
- File operations (`upload_file`, `upload_folder`)

### 4. Skills System

Skills provide specialized guidance for Databricks development tasks. They are markdown files with instructions and examples that Claude can load on demand.

**Skill loading flow:**
1. On startup, skills are copied from `../databricks-skills/` to `./skills/`
2. When a project is created, skills are copied to `project/.claude/skills/`
3. The agent can invoke skills using the `Skill` tool: `skill: "sdp"`

Skills include:
- **asset-bundles**: Databricks Asset Bundles configuration
- **databricks-app-apx**: Full-stack apps with APX framework (FastAPI + React)
- **databricks-app-python**: Python apps with Dash, Streamlit, Flask
- **databricks-python-sdk**: Python SDK patterns
- **mlflow-evaluation**: MLflow evaluation and trace analysis
- **spark-declarative-pipelines**: Spark Declarative Pipelines (SDP) development
- **synthetic-data-generation**: Creating test datasets

### 5. Project Persistence

Projects are stored in the local filesystem with automatic backup to PostgreSQL:

```
projects/
  <project-uuid>/
    .claude/
      skills/        # Copied skills for this project
    src/             # User's code files
    ...
```

**Backup system:**
- After each agent interaction, the project is marked for backup
- A background worker runs every 10 minutes
- Projects are zipped and stored in PostgreSQL (Lakebase)
- On access, missing projects are restored from backup

## Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- [uv](https://github.com/astral-sh/uv) package manager (or pip)
- Databricks workspace with:
  - SQL warehouse (for SQL queries)
  - Cluster (for Python/PySpark execution)
  - Unity Catalog enabled (recommended)
- PostgreSQL database (Lakebase) for project persistence

### Quick Start

#### 1. Clone and Install Dependencies

```bash
# Navigate to the app directory
cd databricks-builder-app

# Install backend dependencies
uv sync
# OR with pip: pip install -e .

# Install sibling packages (from repo root)
cd ..
uv pip install -e databricks-tools-core -e databricks-mcp-server
# OR: pip install -e databricks-tools-core -e databricks-mcp-server

# Install frontend dependencies
cd databricks-builder-app/client
npm install
cd ..
```

#### 2. Configure Environment Variables

Create `.env.local` in the `databricks-builder-app` directory:

```bash
# Copy example
cp .env.example .env.local
```

Edit `.env.local` with your configuration:

```bash
# Databricks Configuration (for local development)
DATABRICKS_HOST=https://your-workspace.cloud.databricks.com
DATABRICKS_TOKEN=dapi...  # Your personal access token

# PostgreSQL Database (Lakebase) - Required for persistence
LAKEBASE_PG_URL=postgresql://user:password@host:5432/database?sslmode=require
LAKEBASE_PROJECT_ID=your-lakebase-project-id

# Projects directory (where agent works)
PROJECTS_BASE_DIR=./projects

# Environment mode
ENV=development

# Skills to load (comma-separated)
ENABLED_SKILLS=spark-declarative-pipelines,synthetic-data-generation
```

**Getting your Databricks token:**
1. Go to your Databricks workspace
2. Click your username → User Settings
3. Go to Access Tokens → Generate New Token
4. Copy the token value

#### 3. Configure Claude Settings (Optional - for Databricks Model Serving)

If you're routing Claude API calls through Databricks Model Serving instead of directly to Anthropic, create `.claude/settings.json` in the **repository root** (not in the app directory):

```bash
# From repo root
mkdir -p .claude
```

Create `.claude/settings.json`:

```json
{
    "env": {
        "ANTHROPIC_MODEL": "databricks-claude-sonnet-4-5",
        "ANTHROPIC_BASE_URL": "https://your-workspace.cloud.databricks.com/serving-endpoints/anthropic",
        "ANTHROPIC_AUTH_TOKEN": "dapi...",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "databricks-claude-opus-4-5",
        "ANTHROPIC_DEFAULT_SONNET_MODEL": "databricks-claude-sonnet-4-5"
    }
}
```

**Notes:**
- `ANTHROPIC_AUTH_TOKEN` should be a Databricks Personal Access Token (PAT), not an Anthropic API key
- `ANTHROPIC_BASE_URL` should point to your Databricks Model Serving endpoint
- If this file doesn't exist, the app will use your Anthropic API key from the environment

**⚠️ Important:** Add `.claude/settings.json` to `.gitignore` - it contains credentials!

#### 4. Start the Development Servers

**Option A: Use the start script (recommended)**

```bash
./scripts/start_dev.sh
```

This starts both backend and frontend in one terminal.

**Option B: Start separately**

Terminal 1 (Backend):
```bash
uvicorn server.app:app --reload --port 8000 --reload-dir server
```

Terminal 2 (Frontend):
```bash
cd client
npm run dev
```

#### 5. Access the App

- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### Configuration Details

#### Databricks Authentication Modes

The app supports two authentication modes:

**1. Local Development (Environment Variables)**
- Uses `DATABRICKS_HOST` and `DATABRICKS_TOKEN` from `.env.local`
- All users share the same credentials
- Good for local testing

**2. Production (Request Headers)**
- Uses `X-Forwarded-User` and `X-Forwarded-Access-Token` headers
- Set automatically by Databricks Apps proxy
- Each user has their own credentials
- Proper multi-user isolation

#### Skills Configuration

Skills are loaded from `../databricks-skills/` and filtered by the `ENABLED_SKILLS` environment variable:

- `databricks-python-sdk`: Patterns for using the Databricks Python SDK
- `spark-declarative-pipelines`: SDP/DLT pipeline development
- `synthetic-data-generation`: Creating test datasets
- `build-databricks-app`: Building Databricks apps

**Adding custom skills:**
1. Create a new directory in `../databricks-skills/`
2. Add a `SKILL.md` file with frontmatter:
   ```markdown
   ---
   name: my-skill
   description: "Description of the skill"
   ---
   
   # Skill content here
   ```
3. Add the skill name to `ENABLED_SKILLS` in `.env.local`

#### Database Setup

The app uses PostgreSQL (Lakebase) for:
- Project metadata
- Conversation history
- Message storage
- Project backups (zipped project files)

**Migrations:**
```bash
# Run migrations (done automatically on startup)
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"
```

### Troubleshooting

#### "MCP connection unstable" or agent not executing tools

This was a known issue with `claude-agent-sdk` in FastAPI contexts. We've implemented a fix:

- ✅ Agent runs in a fresh event loop in a separate thread
- ✅ Context variables (Databricks auth) are properly propagated
- ✅ All MCP tools work correctly

See [EVENT_LOOP_FIX.md](./EVENT_LOOP_FIX.md) for technical details.

#### Skills not loading

Check:
1. `ENABLED_SKILLS` environment variable in `.env.local`
2. Skill names match directory names in `../databricks-skills/`
3. Each skill has a `SKILL.md` file with proper frontmatter
4. Check logs: `Copied X skills to ./skills`

#### Databricks authentication failing

Check:
1. `DATABRICKS_HOST` is correct (no trailing slash)
2. `DATABRICKS_TOKEN` is valid and not expired
3. Token has proper permissions (cluster access, SQL warehouse access, etc.)
4. If using Databricks Model Serving, check `.claude/settings.json` configuration

#### Port already in use

```bash
# Kill processes on ports 8000 and 3000
lsof -ti:8000 | xargs kill -9
lsof -ti:3000 | xargs kill -9
```

### Production Build

```bash
# Build frontend
cd client && npm run build && cd ..

# Run with uvicorn
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

## Project Structure

```
databricks-builder-app/
├── server/                 # FastAPI backend
│   ├── app.py             # Main FastAPI app
│   ├── db/                # Database models and migrations
│   │   ├── models.py      # SQLAlchemy models
│   │   └── database.py    # Session management
│   ├── routers/           # API endpoints
│   │   ├── agent.py       # /api/agent/* (invoke, etc.)
│   │   ├── projects.py    # /api/projects/*
│   │   └── conversations.py
│   └── services/          # Business logic
│       ├── agent.py       # Claude Code session management
│       ├── databricks_tools.py  # MCP tool loading from SDK
│       ├── user.py        # User auth (headers/env vars)
│       ├── skills_manager.py
│       ├── backup_manager.py
│       └── system_prompt.py
├── client/                # React frontend
│   ├── src/
│   │   ├── pages/         # Main pages (ProjectPage, etc.)
│   │   └── components/    # UI components
│   └── package.json
├── alembic/               # Database migrations
├── scripts/               # Utility scripts
│   └── start_dev.sh       # Development startup
├── skills/                # Cached skills (gitignored)
├── projects/              # Project working directories (gitignored)
├── pyproject.toml         # Python dependencies
└── .env.example           # Environment template
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/projects` | GET | List all projects |
| `/api/projects` | POST | Create new project |
| `/api/projects/{id}` | GET | Get project details |
| `/api/projects/{id}/conversations` | GET | List project conversations |
| `/api/conversations` | POST | Create new conversation |
| `/api/conversations/{id}` | GET | Get conversation with messages |
| `/api/agent/invoke` | POST | Send message to agent (SSE stream) |
| `/api/config/user` | GET | Get current user info |

## Related Packages

- **databricks-tools-core**: Core MCP functionality and SQL operations
- **databricks-mcp-server**: MCP server exposing Databricks tools
- **databricks-skills**: Skill definitions for Databricks development
