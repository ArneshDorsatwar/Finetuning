"""
FireWeave LangChain Integration Package

This package provides integration utilities for the Network Security Expert v2 model
with LangChain, RAG pipelines, and various chatbot frameworks.

Usage:
    from fireweave_integration import FireWeaveChat, create_fireweave_agent

    # Simple chat (no dependencies)
    chat = FireWeaveChat()
    response = chat.chat("How do I check traffic flows?")

    # LangChain agent (requires langchain)
    agent, rag = create_fireweave_agent()
    result = agent.invoke({"input": "Run PCI scan", "context": "", "chat_history": []})
"""

from .langchain_fireweave import (
    # Tool definitions
    FIREWEAVE_TOOLS_LANGCHAIN,

    # Simple interfaces (no dependencies)
    FireWeaveRAGContext,
    FireWeaveChatMemory,
    FireWeaveChat,

    # FastAPI
    create_fastapi_routes,
)

# LangChain interfaces (optional)
try:
    from .langchain_fireweave import (
        FireWeaveLLM,
        FireWeaveChatModel,
        FIREWEAVE_LANGCHAIN_TOOLS,
        create_fireweave_agent,
    )
except ImportError:
    FireWeaveLLM = None
    FireWeaveChatModel = None
    FIREWEAVE_LANGCHAIN_TOOLS = []
    create_fireweave_agent = None

__all__ = [
    # Tool definitions
    "FIREWEAVE_TOOLS_LANGCHAIN",

    # Simple interfaces
    "FireWeaveRAGContext",
    "FireWeaveChatMemory",
    "FireWeaveChat",
    "create_fastapi_routes",

    # LangChain interfaces
    "FireWeaveLLM",
    "FireWeaveChatModel",
    "FIREWEAVE_LANGCHAIN_TOOLS",
    "create_fireweave_agent",
]

__version__ = "2.0.0"
