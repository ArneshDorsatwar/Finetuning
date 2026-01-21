#!/usr/bin/env python3
"""
LangChain Integration for FireWeave Network Security Expert v2

This module provides full LangChain integration including:
- Custom LLM wrapper for Ollama
- FireWeave tool definitions
- RAG pipeline with policy/rule context
- Chat memory management
- Streaming support

Compatible with LangChain, LlamaIndex, and direct API usage.
"""

import json
from typing import Any, Dict, List, Optional, Iterator
from pydantic import BaseModel, Field

# =============================================================================
# LANGCHAIN TOOL DEFINITIONS
# =============================================================================

FIREWEAVE_TOOLS_LANGCHAIN = [
    {
        "type": "function",
        "function": {
            "name": "check_traffic_flow",
            "description": "Check if network traffic is allowed between a source and destination IP address through the firewall. Use this when a user asks about connectivity, traffic paths, or whether communication between systems is permitted.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "The source IP address or CIDR range (e.g., '10.0.0.1' or '10.0.0.0/24')"
                    },
                    "destination_ip": {
                        "type": "string",
                        "description": "The destination IP address or CIDR range"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The destination port number (e.g., 443 for HTTPS, 22 for SSH)"
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp", "icmp"],
                        "description": "The network protocol. Defaults to 'tcp' if not specified."
                    }
                },
                "required": ["source_ip", "destination_ip", "port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_attack_path",
            "description": "Analyze potential attack paths from a source to a target in the network. Use this for security assessments, penetration testing planning, or understanding lateral movement risks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "The attack origin - can be 'internet', an IP address, hostname, or security zone name"
                    },
                    "target": {
                        "type": "string",
                        "description": "The target asset - IP address, hostname, security zone, or asset group"
                    },
                    "include_cloud": {
                        "type": "boolean",
                        "description": "Whether to include AWS/Azure/GCP cloud paths in the analysis"
                    }
                },
                "required": ["source", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_compliance_scan",
            "description": "Run a compliance scan against a security framework to identify policy violations and generate audit evidence. Use this for compliance assessments, audit preparation, or security posture reviews.",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci-dss", "soc2", "nist-800-53", "hipaa", "iso27001", "cis"],
                        "description": "The compliance framework to scan against"
                    },
                    "scope": {
                        "type": "string",
                        "description": "The scope of the scan - device group names (comma-separated) or 'all' for entire infrastructure"
                    },
                    "include_evidence": {
                        "type": "boolean",
                        "description": "Whether to generate evidence artifacts for auditors"
                    }
                },
                "required": ["framework", "scope"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_shadowed_rules",
            "description": "Find firewall rules that are shadowed (never matched) by more specific rules positioned above them. Use this for policy optimization and cleanup.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_group": {
                        "type": "string",
                        "description": "The Panorama device group to analyze"
                    },
                    "include_recommendations": {
                        "type": "boolean",
                        "description": "Whether to include safe removal recommendations"
                    }
                },
                "required": ["device_group"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_firewall_rule",
            "description": "Generate a firewall rule configuration for deployment. Use this when a user needs to create, modify, or define a new security policy rule.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "A descriptive name for the rule"
                    },
                    "source_zone": {
                        "type": "string",
                        "description": "The source security zone"
                    },
                    "destination_zone": {
                        "type": "string",
                        "description": "The destination security zone"
                    },
                    "source_address": {
                        "type": "string",
                        "description": "Source IP, CIDR, or address object name"
                    },
                    "destination_address": {
                        "type": "string",
                        "description": "Destination IP, CIDR, or address object name"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service definition (e.g., 'tcp/443', 'application-default', 'any')"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["allow", "deny", "drop"],
                        "description": "The rule action"
                    },
                    "logging": {
                        "type": "boolean",
                        "description": "Whether to enable logging for this rule"
                    }
                },
                "required": ["name", "source_zone", "destination_zone", "source_address", "destination_address", "service", "action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_change_request",
            "description": "Create a ServiceNow change request for firewall changes. Use this to initiate the change management workflow for rule deployments.",
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description of the change"
                    },
                    "justification": {
                        "type": "string",
                        "description": "Business justification for the change"
                    },
                    "rules": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Array of rule configurations to deploy"
                    },
                    "schedule": {
                        "type": "string",
                        "description": "Deployment schedule (e.g., 'immediate', 'next-maintenance-window', or specific datetime)"
                    }
                },
                "required": ["description", "justification", "rules"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_blast_radius",
            "description": "Calculate what assets an attacker could reach if a specific asset is compromised. Use this for risk assessment and incident response planning.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset": {
                        "type": "string",
                        "description": "The potentially compromised asset (IP, hostname, or zone)"
                    },
                    "include_lateral": {
                        "type": "boolean",
                        "description": "Whether to include lateral movement paths in the analysis"
                    }
                },
                "required": ["asset"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_topology",
            "description": "Query network topology information across connected platforms. Use this to understand network architecture and connectivity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "enum": ["aws", "azure", "gcp", "panorama", "all"],
                        "description": "The platform to query"
                    },
                    "region": {
                        "type": "string",
                        "description": "Optional region filter for cloud platforms"
                    }
                },
                "required": ["platform"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_policies",
            "description": "Search firewall policies and rules by various criteria. Use this to find specific rules or understand existing policy configurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (IP, port, rule name, zone, or keyword)"
                    },
                    "device_group": {
                        "type": "string",
                        "description": "Optional device group to search within"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return"
                    }
                },
                "required": ["query"]
            }
        }
    }
]


# =============================================================================
# LANGCHAIN CUSTOM LLM WRAPPER
# =============================================================================

try:
    from langchain_core.language_models.llms import LLM
    from langchain_core.callbacks.manager import CallbackManagerForLLMRun
    from langchain_core.outputs import GenerationChunk

    class FireWeaveLLM(LLM):
        """Custom LangChain LLM wrapper for FireWeave Network Security Expert."""

        model: str = "network-security-expert-v2"
        base_url: str = "http://localhost:11434"
        temperature: float = 0.7
        top_p: float = 0.9
        num_ctx: int = 4096
        streaming: bool = False

        @property
        def _llm_type(self) -> str:
            return "fireweave-ollama"

        @property
        def _identifying_params(self) -> Dict[str, Any]:
            return {
                "model": self.model,
                "temperature": self.temperature,
                "top_p": self.top_p,
            }

        def _call(
            self,
            prompt: str,
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> str:
            """Call the Ollama API."""
            import httpx

            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "top_p": self.top_p,
                        "num_ctx": self.num_ctx,
                    }
                },
                timeout=120
            )

            return response.json()["response"]

        def _stream(
            self,
            prompt: str,
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> Iterator[GenerationChunk]:
            """Stream the Ollama API response."""
            import httpx

            with httpx.stream(
                "POST",
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": True,
                    "options": {
                        "temperature": self.temperature,
                        "top_p": self.top_p,
                        "num_ctx": self.num_ctx,
                    }
                },
                timeout=120
            ) as response:
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        if "response" in data:
                            yield GenerationChunk(text=data["response"])

except ImportError:
    FireWeaveLLM = None
    print("LangChain not installed. Install with: pip install langchain langchain-core")


# =============================================================================
# LANGCHAIN CHAT MODEL WITH TOOL SUPPORT
# =============================================================================

try:
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import (
        AIMessage, HumanMessage, SystemMessage, ToolMessage, BaseMessage
    )
    from langchain_core.outputs import ChatResult, ChatGeneration

    class FireWeaveChatModel(BaseChatModel):
        """Chat model with native tool calling support."""

        model: str = "network-security-expert-v2"
        base_url: str = "http://localhost:11434"
        temperature: float = 0.7
        tools: List[Dict] = Field(default_factory=lambda: FIREWEAVE_TOOLS_LANGCHAIN)

        @property
        def _llm_type(self) -> str:
            return "fireweave-chat"

        def _generate(
            self,
            messages: List[BaseMessage],
            stop: Optional[List[str]] = None,
            run_manager: Optional[Any] = None,
            **kwargs: Any,
        ) -> ChatResult:
            """Generate a response with tool support."""
            import httpx

            # Convert messages to Ollama format
            ollama_messages = []
            for msg in messages:
                if isinstance(msg, SystemMessage):
                    ollama_messages.append({"role": "system", "content": msg.content})
                elif isinstance(msg, HumanMessage):
                    ollama_messages.append({"role": "user", "content": msg.content})
                elif isinstance(msg, AIMessage):
                    ollama_messages.append({"role": "assistant", "content": msg.content})
                elif isinstance(msg, ToolMessage):
                    ollama_messages.append({"role": "tool", "content": msg.content})

            # Call Ollama with tools
            response = httpx.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": ollama_messages,
                    "tools": self.tools,
                    "stream": False,
                    "options": {"temperature": self.temperature}
                },
                timeout=120
            )

            result = response.json()
            content = result.get("message", {}).get("content", "")
            tool_calls = result.get("message", {}).get("tool_calls", [])

            ai_message = AIMessage(
                content=content,
                tool_calls=tool_calls if tool_calls else None
            )

            return ChatResult(generations=[ChatGeneration(message=ai_message)])

        @property
        def _identifying_params(self) -> Dict[str, Any]:
            return {"model": self.model, "temperature": self.temperature}

except ImportError:
    FireWeaveChatModel = None


# =============================================================================
# LANGCHAIN TOOLS
# =============================================================================

try:
    from langchain_core.tools import tool, StructuredTool

    @tool
    def check_traffic_flow(
        source_ip: str,
        destination_ip: str,
        port: int,
        protocol: str = "tcp"
    ) -> str:
        """Check if network traffic is allowed between source and destination."""
        # This would call the actual FireWeave API
        # For now, return a placeholder
        return json.dumps({
            "function": "check_traffic_flow",
            "parameters": {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "port": port,
                "protocol": protocol
            },
            "note": "Call FireWeave API at /api/v1/traffic/check"
        })

    @tool
    def analyze_attack_path(
        source: str,
        target: str,
        include_cloud: bool = True
    ) -> str:
        """Analyze potential attack paths from source to target."""
        return json.dumps({
            "function": "analyze_attack_path",
            "parameters": {
                "source": source,
                "target": target,
                "include_cloud": include_cloud
            },
            "note": "Call FireWeave API at /api/v1/security/attack-path"
        })

    @tool
    def run_compliance_scan(
        framework: str,
        scope: str,
        include_evidence: bool = False
    ) -> str:
        """Run a compliance scan against a security framework."""
        return json.dumps({
            "function": "run_compliance_scan",
            "parameters": {
                "framework": framework,
                "scope": scope,
                "include_evidence": include_evidence
            },
            "note": "Call FireWeave API at /api/v1/compliance/scan"
        })

    @tool
    def create_firewall_rule(
        name: str,
        source_zone: str,
        destination_zone: str,
        source_address: str,
        destination_address: str,
        service: str,
        action: str,
        logging: bool = True
    ) -> str:
        """Generate a firewall rule configuration."""
        return json.dumps({
            "function": "create_firewall_rule",
            "parameters": {
                "name": name,
                "source_zone": source_zone,
                "destination_zone": destination_zone,
                "source_address": source_address,
                "destination_address": destination_address,
                "service": service,
                "action": action,
                "logging": logging
            },
            "note": "Call FireWeave API at /api/v1/rules/create"
        })

    FIREWEAVE_LANGCHAIN_TOOLS = [
        check_traffic_flow,
        analyze_attack_path,
        run_compliance_scan,
        create_firewall_rule,
    ]

except ImportError:
    FIREWEAVE_LANGCHAIN_TOOLS = []


# =============================================================================
# RAG CONTEXT BUILDER
# =============================================================================

class FireWeaveRAGContext:
    """Build RAG context from FireWeave data."""

    def __init__(self, api_base_url: str = "http://localhost:8000"):
        self.api_base_url = api_base_url

    def get_relevant_policies(self, query: str, limit: int = 5) -> List[Dict]:
        """Retrieve relevant firewall policies for the query."""
        # In production, this would call FireWeave's search API
        # or use a vector store with policy embeddings
        return [
            {
                "type": "policy_context",
                "content": f"Relevant policies for: {query}",
                "source": "fireweave_policy_db"
            }
        ]

    def get_topology_context(self, scope: str = "all") -> Dict:
        """Get network topology context."""
        return {
            "type": "topology_context",
            "platforms": ["panorama", "aws", "azure", "gcp"],
            "device_groups": 247,
            "total_rules": 52847
        }

    def get_compliance_status(self, framework: str = "all") -> Dict:
        """Get current compliance status."""
        return {
            "type": "compliance_context",
            "frameworks": {
                "pci-dss": {"score": 94, "findings": 3},
                "soc2": {"score": 98, "findings": 1},
                "nist": {"score": 91, "findings": 5}
            }
        }

    def build_context(self, query: str) -> str:
        """Build full RAG context for a query."""
        policies = self.get_relevant_policies(query)
        topology = self.get_topology_context()
        compliance = self.get_compliance_status()

        context = f"""
<fireweave_context>
<topology>
Platforms: {', '.join(topology['platforms'])}
Device Groups: {topology['device_groups']}
Total Rules Managed: {topology['total_rules']}
</topology>

<compliance_status>
PCI-DSS Score: {compliance['frameworks']['pci-dss']['score']}%
SOC2 Score: {compliance['frameworks']['soc2']['score']}%
NIST Score: {compliance['frameworks']['nist']['score']}%
</compliance_status>

<relevant_policies>
{json.dumps(policies, indent=2)}
</relevant_policies>
</fireweave_context>
"""
        return context


# =============================================================================
# COMPLETE LANGCHAIN AGENT SETUP
# =============================================================================

def create_fireweave_agent(
    model_name: str = "network-security-expert-v2",
    ollama_base_url: str = "http://localhost:11434",
    enable_rag: bool = True,
    verbose: bool = False
):
    """Create a complete LangChain agent for FireWeave."""

    try:
        from langchain.agents import AgentExecutor, create_tool_calling_agent
        from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
        from langchain_community.chat_models import ChatOllama
    except ImportError:
        raise ImportError("Install langchain: pip install langchain langchain-community")

    # Create the chat model
    llm = ChatOllama(
        model=model_name,
        base_url=ollama_base_url,
        temperature=0.7,
    )

    # System prompt
    system_prompt = """You are a Network Security Expert AI integrated with FireWeave - an enterprise firewall automation platform.

You have access to the following capabilities:
- Check traffic flows across firewalls and cloud platforms
- Analyze attack paths and blast radius
- Run compliance scans (PCI-DSS, SOC2, NIST, HIPAA)
- Find shadowed and unused firewall rules
- Create and deploy firewall rules
- Submit ServiceNow change requests

When users ask questions:
1. First understand what they need
2. Use the appropriate tools to gather information
3. Provide detailed explanations with security context
4. Reference compliance requirements when relevant
5. Always consider the security implications

{context}

Current conversation:
{chat_history}

User question: {input}

{agent_scratchpad}"""

    # Create prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    # Bind tools to the model
    llm_with_tools = llm.bind_tools(FIREWEAVE_LANGCHAIN_TOOLS)

    # Create the agent
    agent = create_tool_calling_agent(llm_with_tools, FIREWEAVE_LANGCHAIN_TOOLS, prompt)

    # RAG context builder
    rag_context = FireWeaveRAGContext() if enable_rag else None

    # Create executor
    executor = AgentExecutor(
        agent=agent,
        tools=FIREWEAVE_LANGCHAIN_TOOLS,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=10,
    )

    return executor, rag_context


# =============================================================================
# CHAT MEMORY MANAGEMENT
# =============================================================================

class FireWeaveChatMemory:
    """Manage chat history for FireWeave conversations."""

    def __init__(self, max_history: int = 20):
        self.max_history = max_history
        self.sessions: Dict[str, List[Dict]] = {}

    def add_message(self, session_id: str, role: str, content: str):
        """Add a message to session history."""
        if session_id not in self.sessions:
            self.sessions[session_id] = []

        self.sessions[session_id].append({
            "role": role,
            "content": content
        })

        # Trim old messages
        if len(self.sessions[session_id]) > self.max_history:
            self.sessions[session_id] = self.sessions[session_id][-self.max_history:]

    def get_history(self, session_id: str) -> List[Dict]:
        """Get session history."""
        return self.sessions.get(session_id, [])

    def clear_session(self, session_id: str):
        """Clear session history."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_langchain_messages(self, session_id: str) -> List:
        """Convert history to LangChain message format."""
        try:
            from langchain_core.messages import HumanMessage, AIMessage
        except ImportError:
            return []

        messages = []
        for msg in self.get_history(session_id):
            if msg["role"] == "user":
                messages.append(HumanMessage(content=msg["content"]))
            elif msg["role"] == "assistant":
                messages.append(AIMessage(content=msg["content"]))
        return messages


# =============================================================================
# SIMPLE CHAT INTERFACE (No LangChain Required)
# =============================================================================

class FireWeaveChat:
    """Simple chat interface using Ollama directly - no LangChain dependency."""

    def __init__(
        self,
        model: str = "network-security-expert-v2",
        base_url: str = "http://localhost:11434",
        enable_tools: bool = True
    ):
        self.model = model
        self.base_url = base_url
        self.enable_tools = enable_tools
        self.memory = FireWeaveChatMemory()
        self.rag = FireWeaveRAGContext()

        # System message
        self.system_message = """You are a Network Security Expert AI integrated with FireWeave - an enterprise firewall automation platform.

**Your Capabilities:**
- Deep understanding of network security CONCEPTS and THEORY
- Expertise in compliance frameworks (PCI-DSS, SOC2, NIST, HIPAA, ISO 27001)
- Multi-cloud security (AWS, Azure, GCP) and Palo Alto Panorama
- Attack path analysis and blast radius calculation
- ServiceNow integration for change management

**Your Approach:**
1. REASON step-by-step through complex problems
2. Explain the WHY behind security decisions
3. Reference relevant compliance requirements
4. Use FireWeave functions when action is needed
5. Consider security trade-offs and risks

When you need to perform an action, call the appropriate function."""

    def chat(
        self,
        message: str,
        session_id: str = "default",
        include_context: bool = True
    ) -> Dict:
        """Send a message and get a response."""
        import httpx

        # Add user message to history
        self.memory.add_message(session_id, "user", message)

        # Build messages list
        messages = [{"role": "system", "content": self.system_message}]

        # Add RAG context if enabled
        if include_context:
            context = self.rag.build_context(message)
            messages[0]["content"] += f"\n\n{context}"

        # Add history
        for msg in self.memory.get_history(session_id)[:-1]:  # Exclude current message
            messages.append(msg)

        # Add current message
        messages.append({"role": "user", "content": message})

        # Prepare request
        request_data = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        }

        # Add tools if enabled
        if self.enable_tools:
            request_data["tools"] = FIREWEAVE_TOOLS_LANGCHAIN

        # Call Ollama
        response = httpx.post(
            f"{self.base_url}/api/chat",
            json=request_data,
            timeout=120
        )

        result = response.json()
        assistant_content = result.get("message", {}).get("content", "")
        tool_calls = result.get("message", {}).get("tool_calls", [])

        # Add assistant response to history
        self.memory.add_message(session_id, "assistant", assistant_content)

        return {
            "content": assistant_content,
            "tool_calls": tool_calls,
            "session_id": session_id
        }

    def chat_stream(
        self,
        message: str,
        session_id: str = "default"
    ) -> Iterator[str]:
        """Stream a response."""
        import httpx

        self.memory.add_message(session_id, "user", message)

        messages = [{"role": "system", "content": self.system_message}]
        for msg in self.memory.get_history(session_id)[:-1]:
            messages.append(msg)
        messages.append({"role": "user", "content": message})

        full_response = ""
        with httpx.stream(
            "POST",
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": True
            },
            timeout=120
        ) as response:
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    if "message" in data and "content" in data["message"]:
                        chunk = data["message"]["content"]
                        full_response += chunk
                        yield chunk

        self.memory.add_message(session_id, "assistant", full_response)


# =============================================================================
# FASTAPI INTEGRATION
# =============================================================================

def create_fastapi_routes():
    """Create FastAPI routes for FireWeave AI chat."""

    try:
        from fastapi import APIRouter, HTTPException
        from fastapi.responses import StreamingResponse
        from pydantic import BaseModel
    except ImportError:
        return None

    router = APIRouter(prefix="/api/ai", tags=["AI Chat"])
    chat_instance = FireWeaveChat()

    class ChatRequest(BaseModel):
        message: str
        session_id: Optional[str] = "default"
        include_context: bool = True
        stream: bool = False

    class ChatResponse(BaseModel):
        content: str
        tool_calls: List[Dict] = []
        session_id: str

    @router.post("/chat", response_model=ChatResponse)
    async def chat_endpoint(request: ChatRequest):
        """Send a message to the AI chat."""
        if request.stream:
            async def generate():
                for chunk in chat_instance.chat_stream(
                    request.message,
                    request.session_id
                ):
                    yield f"data: {json.dumps({'content': chunk})}\n\n"
                yield "data: [DONE]\n\n"
            return StreamingResponse(generate(), media_type="text/event-stream")

        result = chat_instance.chat(
            request.message,
            request.session_id,
            request.include_context
        )
        return ChatResponse(**result)

    @router.delete("/session/{session_id}")
    async def clear_session(session_id: str):
        """Clear a chat session."""
        chat_instance.memory.clear_session(session_id)
        return {"status": "cleared", "session_id": session_id}

    @router.get("/health")
    async def health_check():
        """Check if the AI service is healthy."""
        import httpx
        try:
            response = httpx.get(f"{chat_instance.base_url}/api/tags", timeout=5)
            models = [m["name"] for m in response.json().get("models", [])]
            return {
                "status": "healthy",
                "ollama": "connected",
                "models": models,
                "fireweave_model": chat_instance.model in models
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    return router


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("FireWeave LangChain Integration Examples")
    print("=" * 60)

    # Example 1: Simple Chat (No LangChain)
    print("\n[Example 1] Simple Chat Interface:")
    print("-" * 40)
    print("""
from langchain_fireweave import FireWeaveChat

chat = FireWeaveChat(model="network-security-expert-v2")
response = chat.chat("Can 10.1.1.100 reach 192.168.1.50 on port 443?")
print(response["content"])

# With tool calling
if response["tool_calls"]:
    print("Tools called:", response["tool_calls"])
""")

    # Example 2: LangChain Agent
    print("\n[Example 2] LangChain Agent with Tools:")
    print("-" * 40)
    print("""
from langchain_fireweave import create_fireweave_agent

agent, rag = create_fireweave_agent(
    model_name="network-security-expert-v2",
    enable_rag=True,
    verbose=True
)

# Get RAG context
context = rag.build_context("PCI compliance")

# Run agent
result = agent.invoke({
    "input": "Run a PCI-DSS compliance scan on the DMZ firewall",
    "context": context,
    "chat_history": []
})
print(result["output"])
""")

    # Example 3: Streaming with Memory
    print("\n[Example 3] Streaming with Chat Memory:")
    print("-" * 40)
    print("""
from langchain_fireweave import FireWeaveChat

chat = FireWeaveChat()

# First message
response1 = chat.chat("What's the blast radius if 10.1.1.50 is compromised?", session_id="user123")
print(response1["content"])

# Follow-up (remembers context)
response2 = chat.chat("How can we contain that?", session_id="user123")
print(response2["content"])

# Streaming
for chunk in chat.chat_stream("Explain our PCI compliance status", session_id="user123"):
    print(chunk, end="", flush=True)
""")

    # Example 4: FastAPI Integration
    print("\n[Example 4] FastAPI Integration:")
    print("-" * 40)
    print("""
from fastapi import FastAPI
from langchain_fireweave import create_fastapi_routes

app = FastAPI()
ai_routes = create_fastapi_routes()
if ai_routes:
    app.include_router(ai_routes)

# Then run with: uvicorn main:app --reload
# Endpoints:
#   POST /api/ai/chat - Send chat message
#   DELETE /api/ai/session/{id} - Clear session
#   GET /api/ai/health - Health check
""")

    # Example 5: Direct Ollama with Tools
    print("\n[Example 5] Direct Ollama API with Tool Calling:")
    print("-" * 40)
    print("""
import httpx
from langchain_fireweave import FIREWEAVE_TOOLS_LANGCHAIN

response = httpx.post(
    "http://localhost:11434/api/chat",
    json={
        "model": "network-security-expert-v2",
        "messages": [
            {"role": "user", "content": "Check if web-server can reach database on port 5432"}
        ],
        "tools": FIREWEAVE_TOOLS_LANGCHAIN,
        "stream": False
    }
)

result = response.json()
print("Response:", result["message"]["content"])
if result["message"].get("tool_calls"):
    print("Tool calls:", result["message"]["tool_calls"])
""")

    # Example 6: LlamaIndex Integration
    print("\n[Example 6] LlamaIndex Integration:")
    print("-" * 40)
    print("""
# LlamaIndex can use the same Ollama endpoint

from llama_index.llms.ollama import Ollama
from llama_index.core.tools import FunctionTool

llm = Ollama(model="network-security-expert-v2", base_url="http://localhost:11434")

# Define tools from our schema
def check_traffic(source_ip: str, dest_ip: str, port: int) -> str:
    '''Check traffic flow between IPs'''
    # Call FireWeave API
    return f"Traffic from {source_ip} to {dest_ip}:{port} - ALLOWED"

traffic_tool = FunctionTool.from_defaults(fn=check_traffic)

# Use with agent
from llama_index.core.agent import ReActAgent
agent = ReActAgent.from_tools([traffic_tool], llm=llm, verbose=True)
response = agent.chat("Can 10.0.0.1 reach 192.168.1.1 on port 443?")
""")

    print("\n" + "=" * 60)
    print("Installation Requirements:")
    print("=" * 60)
    print("""
# Core (no dependencies)
pip install httpx pydantic

# For LangChain integration
pip install langchain langchain-core langchain-community

# For FastAPI integration
pip install fastapi uvicorn

# For LlamaIndex integration
pip install llama-index llama-index-llms-ollama
""")

    print("\n" + "=" * 60)
    print("Quick Start:")
    print("=" * 60)
    print("""
1. Start Ollama with your fine-tuned model:
   ollama run network-security-expert-v2

2. Test with simple chat:
   from langchain_fireweave import FireWeaveChat
   chat = FireWeaveChat()
   print(chat.chat("How do I check traffic flows in FireWeave?")["content"])

3. Or use with LangChain:
   from langchain_fireweave import create_fireweave_agent
   agent, _ = create_fireweave_agent()
   agent.invoke({"input": "Run PCI scan", "context": "", "chat_history": []})
""")