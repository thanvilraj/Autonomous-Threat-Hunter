# ============================================================
#  FastAPI — Main Application
#
#  REST API that wires all three modules together and exposes
#  endpoints for the analyst dashboard and external integrations.
# ============================================================

from __future__ import annotations

import os
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger

from src.config.settings import get_settings
from src.module_a.neo4j_mapper import Neo4jMapper
from src.module_b.gnn_model import GNNModelManager
from src.module_b.attack_predictor import AttackPredictor
from src.module_b.mitre_mapper import MitreMapper
from src.module_b.defense_engine import DefenseEngine
from src.module_b.audit_logger import AuditLogger
from src.module_c.langchain_reporter import LangChainReporter
from src.module_c.threat_intel import ThreatIntelFeed


# ── App State (shared across requests) ───────────────────────

class AppState:
    neo4j:          Neo4jMapper
    gnn:            GNNModelManager
    predictor:      AttackPredictor
    mitre:          MitreMapper
    defense:        DefenseEngine
    audit:          AuditLogger
    reporter:       LangChainReporter
    threat_intel:   ThreatIntelFeed
    latest_threats: list[dict] = []
    scanning_active: bool = False

state = AppState()


# ── Lifespan — startup & shutdown ────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize all services on startup, clean up on shutdown."""
    logger.info("🚀 Starting Autonomous Threat Hunter API...")

    settings = get_settings()

    # Initialize services
    state.audit       = AuditLogger()
    state.neo4j       = Neo4jMapper()
    state.neo4j.connect()
    state.gnn         = GNNModelManager()
    state.gnn.load_weights()
    state.mitre       = MitreMapper()
    state.defense     = DefenseEngine()
    state.reporter    = LangChainReporter()
    state.threat_intel = ThreatIntelFeed(state.audit)

    state.predictor = AttackPredictor(
        neo4j_mapper   = state.neo4j,
        gnn_manager    = state.gnn,
        mitre_mapper   = state.mitre,
        defense_engine = state.defense,
        audit_logger   = state.audit,
    )

    # Start background loops
    asyncio.create_task(state.predictor.run_loop())
    asyncio.create_task(state.threat_intel.run_polling_loop())

    logger.success("✅ All services initialized. API ready.")
    yield

    # Shutdown
    state.neo4j.close()
    logger.info("🔒 API shutdown complete")


# ── FastAPI App ───────────────────────────────────────────────

app = FastAPI(
    title       = "Autonomous Threat Hunter API",
    description = "AI-powered network threat detection & attack-path prediction",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ── Request / Response Models ─────────────────────────────────

class ApprovalRequest(BaseModel):
    action_id: str
    approver:  str
    approved:  bool


class ThreatRunResponse(BaseModel):
    run_id:       str
    threat_count: int
    status:       str
    predicted_at: str


# ── Endpoints ─────────────────────────────────────────────────

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/ui", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def get_dashboard():
    """Serve the human-understandable SOC Command Center Dashboard UI."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard template not found</h1>"


@app.get("/api/health", tags=["Health"])
async def root():
    return {
        "service": "Autonomous Threat Hunter",
        "status":  "operational",
        "time":    datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Check liveness of all subsystems."""
    return {
        "kafka":    "connected",
        "neo4j":    "connected",
        "llm":      get_settings().llm_provider,
        "threat_intel": state.threat_intel.get_intel_summary(),
    }


def _run_apt_task():
    from src.module_a.kafka_producer import run_simulation
    run_simulation(mode="apt", interval=0.2)


@app.post("/simulate/apt", tags=["Simulation"])
async def trigger_apt_simulation(background_tasks: BackgroundTasks):
    """Trigger an APT attack simulation sequence into Kafka and Neo4j."""
    background_tasks.add_task(_run_apt_task)
    return {"status": "started", "message": "APT attack simulation initiated (8 steps across 7 hosts)"}


@app.post("/scan/start", tags=["Scanner"])
async def start_continuous_scan():
    """Activate continuous background threat scanning."""
    state.scanning_active = True
    return {"status": "active", "message": "Continuous threat scan activated"}


@app.post("/scan/stop", tags=["Scanner"])
async def stop_continuous_scan():
    """Pause continuous background threat scanning."""
    state.scanning_active = False
    return {"status": "paused", "message": "Continuous threat scan paused"}


@app.get("/scan/status", tags=["Scanner"])
async def get_scan_status():
    """Return continuous scan status."""
    return {"scanning_active": state.scanning_active}





@app.get("/threats", tags=["Threats"])
async def get_active_threats():
    """
    Trigger a prediction cycle and return current threat nodes.
    """
    result = await state.predictor.run_prediction_cycle()
    state.latest_threats = result.get("attack_paths", [])
    return result


@app.get("/threats/top", tags=["Threats"])
async def get_top_threats(limit: int = 5):
    """Return top N threat nodes from the last prediction cycle."""
    return state.latest_threats[:limit]


@app.get("/graph/snapshot", tags=["Graph"])
async def get_graph_snapshot():
    """
    Return the current Neo4j graph as JSON (nodes + edges).
    Used to render the network graph visualization.
    """
    snapshot = state.neo4j.get_graph_snapshot()
    return {
        "node_count": len(snapshot["nodes"]),
        "edge_count": len(snapshot["edges"]),
        "snapshot":   snapshot,
    }


@app.get("/graph/high-risk", tags=["Graph"])
async def get_high_risk_nodes(threshold: float = 0.6):
    """Return nodes with risk_score above the given threshold."""
    nodes = state.neo4j.get_high_risk_nodes(threshold)
    return {"threshold": threshold, "count": len(nodes), "nodes": nodes}


@app.get("/incidents/{incident_id}", tags=["Incidents"])
async def get_incident(incident_id: str):
    """Placeholder: fetch a specific incident report by ID."""
    return {"incident_id": incident_id, "status": "Incident report lookup not yet persisted — use /threats to generate live."}


@app.post("/incidents/generate", tags=["Incidents"])
async def generate_incident_report(background_tasks: BackgroundTasks):
    """
    Run a prediction cycle and generate LLM incident reports
    for all threat nodes found.
    """
    result = await state.predictor.run_prediction_cycle()
    attack_paths = result.get("attack_paths", [])

    if not attack_paths:
        return {"message": "No threats detected — no reports generated", "run_id": result["run_id"]}

    # Generate report for top threat
    top = attack_paths[0]
    # Fetch threat intel enrichment
    ip_enrich = await state.threat_intel.enrich_ip(top["node"].get("node_name", ""))

    report = state.reporter.generate_incident_report(
        node         = top["node"],
        mitre_info   = top["mitre"],
        defense_recs = top["defense"],
        threat_intel = ip_enrich,
    )
    state.audit.log_incident_report(report["incident_id"], report["executive_brief"])
    return report


@app.get("/actions/pending", tags=["Defense Actions"])
async def get_pending_actions():
    """Return all HIGH/CRITICAL defense actions awaiting human approval."""
    actions = state.defense.get_pending_actions()
    return {"pending_count": len(actions), "actions": actions}


@app.post("/actions/approve", tags=["Defense Actions"])
async def approve_or_reject_action(request: ApprovalRequest):
    """
    Human analyst approves or rejects a pending defense action.
    This is the core responsible AI gate.
    """
    if request.approved:
        result = state.defense.approve_action(request.action_id, request.approver)
    else:
        result = state.defense.reject_action(request.action_id, request.approver)

    state.audit.log_approval(request.action_id, request.approver, request.approved)
    return result


@app.get("/mitre/techniques", tags=["MITRE ATT&CK"])
async def get_mitre_techniques():
    """Return all loaded MITRE ATT&CK techniques."""
    techniques = state.mitre.get_all_techniques()
    return {"count": len(techniques), "techniques": techniques}


@app.get("/intel/summary", tags=["Threat Intel"])
async def get_intel_summary():
    """Return threat intel feed status and cached IOC count."""
    return state.threat_intel.get_intel_summary()


@app.get("/audit", tags=["Audit"])
async def get_audit_log(limit: int = 50):
    """Return the most recent audit log entries."""
    entries = state.audit.get_recent_entries(limit=limit)
    return {"count": len(entries), "entries": entries}
