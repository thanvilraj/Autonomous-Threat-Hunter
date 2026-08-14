# ============================================================
#  Module B — Attack Predictor
#
#  Orchestrates: Neo4j snapshot → GNN inference → MITRE mapping
#  → ranked list of predicted next targets
# ============================================================

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from src.config.settings import get_settings
from src.module_a.neo4j_mapper import Neo4jMapper
from src.module_b.gnn_model import GNNModelManager
from src.module_b.mitre_mapper import MitreMapper
from src.module_b.defense_engine import DefenseEngine
from src.module_b.audit_logger import AuditLogger


class AttackPredictor:
    """
    Main orchestrator for Module B.
    Pulls graph from Neo4j, runs GNN, maps to MITRE ATT&CK,
    and feeds results to the Defense Engine.
    """

    def __init__(
        self,
        neo4j_mapper: Neo4jMapper,
        gnn_manager:  GNNModelManager,
        mitre_mapper: MitreMapper,
        defense_engine: DefenseEngine,
        audit_logger:   AuditLogger,
    ):
        self.settings       = get_settings()
        self.neo4j          = neo4j_mapper
        self.gnn            = gnn_manager
        self.mitre          = mitre_mapper
        self.defense        = defense_engine
        self.audit          = audit_logger
        self._last_run: Optional[datetime] = None

    async def run_prediction_cycle(self) -> dict:
        """
        Full prediction pipeline — runs every N seconds.

        Returns a structured threat report dict.
        """
        run_id = f"pred-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        logger.info(f"🔄 Starting prediction cycle [{run_id}]")

        # 1. Pull graph snapshot from Neo4j
        snapshot = self.neo4j.get_graph_snapshot()
        if not snapshot["nodes"]:
            logger.warning("⚠️  Empty graph — no prediction this cycle")
            return {"run_id": run_id, "threats": [], "status": "empty_graph"}

        # 2. Run GNN inference
        predictions = self.gnn.predict(snapshot)
        threat_nodes = [p for p in predictions if p["is_threat"]]

        # 3. Map to MITRE ATT&CK + build attack paths
        attack_paths = []
        for node in threat_nodes[:10]:   # Top 10 threats
            mitre_info = self.mitre.map_node_to_attack(node)
            defense_recs = self.defense.generate_recommendations(node, mitre_info)

            attack_paths.append({
                "node":         node,
                "mitre":        mitre_info,
                "defense":      defense_recs,
                "predicted_at": datetime.now(timezone.utc).isoformat(),
            })

        # 4. Log to audit trail
        self.audit.log_prediction(run_id, threat_nodes, attack_paths)

        self._last_run = datetime.now(timezone.utc)
        result = {
            "run_id":         run_id,
            "total_nodes":    len(predictions),
            "threat_count":   len(threat_nodes),
            "attack_paths":   attack_paths,
            "graph_nodes":    len(snapshot["nodes"]),
            "graph_edges":    len(snapshot["edges"]),
            "predicted_at":   self._last_run.isoformat(),
            "status":         "ok",
        }

        logger.success(
            f"✅ Cycle [{run_id}] complete | threats={len(threat_nodes)} | "
            f"nodes={len(snapshot['nodes'])} | edges={len(snapshot['edges'])}"
        )
        return result

    async def run_loop(self):
        """Continuous prediction loop — runs every PREDICTION_INTERVAL_SEC seconds."""
        interval = self.settings.prediction_interval_sec
        logger.info(f"⏱  Prediction loop started (every {interval}s)")
        while True:
            try:
                await self.run_prediction_cycle()
            except Exception as e:
                logger.exception(f"💥 Prediction cycle failed: {e}")
            await asyncio.sleep(interval)
