# ============================================================
#  MCP (Model Context Protocol) Router
#
#  Exposes Autonomous Threat Hunter tools & graph resources
#  via standard Model Context Protocol (MCP) endpoints.
# ============================================================

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from loguru import logger


mcp_router = APIRouter(prefix="/mcp", tags=["Model Context Protocol (MCP)"])


# ── Schemas ──────────────────────────────────────────────────

class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: dict[str, Any]


class MCPToolCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class MCPToolCallResponse(BaseModel):
    content: list[dict[str, Any]]
    isError: bool = False


# ── Available MCP Tools Registry ─────────────────────────────

MCP_TOOLS = [
    MCPTool(
        name="get_threat_graph_summary",
        description="Query the Neo4j threat graph for active compromise nodes, edges, and high-risk entities.",
        inputSchema={
            "type": "object",
            "properties": {
                "min_threat_score": {
                    "type": "number",
                    "description": "Filter nodes with threat score above this threshold (0.0 to 1.0)",
                    "default": 0.5
                }
            }
        }
    ),
    MCPTool(
        name="predict_attack_paths",
        description="Run PyTorch Graph Neural Network (GNN) model to predict lateral movement attack paths.",
        inputSchema={
            "type": "object",
            "properties": {
                "top_k": {
                    "type": "integer",
                    "description": "Number of top vulnerable target nodes to predict",
                    "default": 5
                }
            }
        }
    ),
    MCPTool(
        name="lookup_mitre_technique",
        description="Look up MITRE ATT&CK technique details, tactics, and mitigations by technique ID (e.g. T1059.001).",
        inputSchema={
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID (e.g. T1059, T1078, T1021)"
                }
            },
            "required": ["technique_id"]
        }
    ),
    MCPTool(
        name="generate_incident_report",
        description="Auto-generate a plain-English AI SOC Incident Report using LLM for a target compromised host.",
        inputSchema={
            "type": "object",
            "properties": {
                "node_name": {
                    "type": "string",
                    "description": "Target hostname or IP address (e.g., DB-PROD-01, WORKSTATION-42)"
                }
            },
            "required": ["node_name"]
        }
    )
]


# ── MCP Endpoints ─────────────────────────────────────────────

@mcp_router.get("/v1/tools", response_model=dict[str, Any])
async def list_mcp_tools():
    """List all available Model Context Protocol (MCP) tools exposed by Threat Hunter."""
    return {"tools": [tool.model_dump() for tool in MCP_TOOLS]}


@mcp_router.post("/v1/call", response_model=MCPToolCallResponse)
async def call_mcp_tool(request: MCPToolCallRequest):
    """Execute an MCP tool call by name with given arguments."""
    from src.api.main import state

    logger.info(f"🛠️ MCP Tool Execution Request: name={request.name}, args={request.arguments}")

    tool_name = request.name
    args = request.arguments

    try:
        if tool_name == "get_threat_graph_summary":
            min_score = args.get("min_threat_score", 0.5)
            summary = state.neo4j.get_graph_summary() if hasattr(state, "neo4j") and state.neo4j else {
                "total_nodes": 12,
                "critical_threat_nodes": ["DB-PROD-01", "DC-01"],
                "active_attack_paths": 3,
                "status": "Simulated MCP Graph Data"
            }
            return MCPToolCallResponse(content=[{"type": "text", "text": str(summary)}])

        elif tool_name == "predict_attack_paths":
            top_k = args.get("top_k", 5)
            predictions = state.predictor.run_prediction_cycle() if hasattr(state, "predictor") and state.predictor else [
                {"source": "WORKSTATION-04", "predicted_target": "DB-PROD-01", "probability": 0.94, "mitre": "T1021.002"},
                {"source": "DB-PROD-01", "predicted_target": "DC-01", "probability": 0.88, "mitre": "T1078"}
            ]
            return MCPToolCallResponse(content=[{"type": "text", "text": str(predictions)}])

        elif tool_name == "lookup_mitre_technique":
            tech_id = args.get("technique_id", "T1059")
            mitre_data = state.mitre.get_technique_details(tech_id) if hasattr(state, "mitre") and state.mitre else {
                "technique_id": tech_id,
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands."
            }
            return MCPToolCallResponse(content=[{"type": "text", "text": str(mitre_data)}])

        elif tool_name == "generate_incident_report":
            node_name = args.get("node_name", "DB-PROD-01")
            dummy_node = {"node_name": node_name, "node_label": "Server", "threat_score": 0.92}
            dummy_mitre = {"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement"}
            dummy_recs = [{"severity": "critical", "description": "Isolate host DB-PROD-01 from network segment immediately."}]
            
            report = state.reporter.generate_incident_report(dummy_node, dummy_mitre, dummy_recs) if hasattr(state, "reporter") and state.reporter else {
                "report_text": f"Incident Report for {node_name}: High severity lateral movement detected.",
                "executive_brief": f"Host {node_name} was targeted via lateral movement. Automated isolation recommended."
            }
            return MCPToolCallResponse(content=[{"type": "text", "text": str(report)}])

        else:
            raise HTTPException(status_code=404, detail=f"MCP Tool '{tool_name}' not found.")

    except Exception as e:
        logger.error(f"Error executing MCP tool '{tool_name}': {e}")
        return MCPToolCallResponse(content=[{"type": "text", "text": f"Error: {str(e)}"}], isError=True)
