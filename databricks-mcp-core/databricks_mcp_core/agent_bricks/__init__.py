"""
Agent Bricks - Manage Genie Spaces, Knowledge Assistants, and Multi-Agent Supervisors.

This module provides a unified interface for managing Agent Bricks resources:
- Knowledge Assistants (KA): Document-based Q&A systems
- Multi-Agent Supervisors (MAS): Multi-agent orchestration
- Genie Spaces: SQL-based data exploration
"""

from .manager import AgentBricksManager
from .models import (
    # Enums
    EndpointStatus,
    Permission,
    TileType,
    # Data classes
    GenieIds,
    KAIds,
    MASIds,
    # TypedDicts
    BaseAgentDict,
    CuratedQuestionDict,
    EvaluationRunDict,
    GenieListInstructionsResponseDict,
    GenieListQuestionsResponseDict,
    GenieSpaceDict,
    InstructionDict,
    KnowledgeAssistantDict,
    KnowledgeAssistantExampleDict,
    KnowledgeAssistantListExamplesResponseDict,
    KnowledgeAssistantResponseDict,
    KnowledgeAssistantStatusDict,
    KnowledgeSourceDict,
    ListEvaluationRunsResponseDict,
    MultiAgentSupervisorDict,
    MultiAgentSupervisorExampleDict,
    MultiAgentSupervisorListExamplesResponseDict,
    MultiAgentSupervisorResponseDict,
    MultiAgentSupervisorStatusDict,
    TileDict,
)

__all__ = [
    # Main class
    "AgentBricksManager",
    # Enums
    "EndpointStatus",
    "Permission",
    "TileType",
    # Data classes
    "GenieIds",
    "KAIds",
    "MASIds",
    # TypedDicts
    "BaseAgentDict",
    "CuratedQuestionDict",
    "EvaluationRunDict",
    "GenieListInstructionsResponseDict",
    "GenieListQuestionsResponseDict",
    "GenieSpaceDict",
    "InstructionDict",
    "KnowledgeAssistantDict",
    "KnowledgeAssistantExampleDict",
    "KnowledgeAssistantListExamplesResponseDict",
    "KnowledgeAssistantResponseDict",
    "KnowledgeAssistantStatusDict",
    "KnowledgeSourceDict",
    "ListEvaluationRunsResponseDict",
    "MultiAgentSupervisorDict",
    "MultiAgentSupervisorExampleDict",
    "MultiAgentSupervisorListExamplesResponseDict",
    "MultiAgentSupervisorResponseDict",
    "MultiAgentSupervisorStatusDict",
    "TileDict",
]
