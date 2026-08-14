# ============================================================
#  Module B — Audit Logger
#
#  Immutable append-only audit trail for all AI decisions.
#  Format: JSONL (one JSON object per line)
#  Rule: Nothing is ever deleted or modified post-write.
# ============================================================

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from src.config.settings import get_settings


class AuditLogger:
    """
    Append-only audit logger for all AI predictions, actions, and approvals.

    Compliance requirements:
      - Every AI decision is logged with model version and confidence
      - Human approvals and rejections are recorded
      - Log file is append-only (no modifications)
      - Log rotation at 100MB
    """

    def __init__(self):
        self.settings   = get_settings()
        self.log_path   = Path(self.settings.audit_log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"📋 Audit logger initialized: {self.log_path}")

    def _write(self, entry: dict) -> None:
        """Append one JSON line to the audit log file."""
        entry["audit_timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def log_prediction(
        self,
        run_id:       str,
        threat_nodes: list[dict],
        attack_paths: list[dict],
    ) -> None:
        """Log a GNN prediction cycle."""
        self._write({
            "event":        "prediction_cycle",
            "run_id":       run_id,
            "threat_count": len(threat_nodes),
            "top_threats":  threat_nodes[:5],
            "attack_paths": [
                {
                    "node":       ap["node"]["node_name"],
                    "score":      ap["node"]["threat_score"],
                    "technique":  ap["mitre"].get("technique_id"),
                    "tactic":     ap["mitre"].get("tactic"),
                }
                for ap in attack_paths
            ],
            "model_info":   {
                "architecture":  "GraphSAGE",
                "threshold":     self.settings.threat_score_threshold,
            },
        })

    def log_action_created(self, action: dict) -> None:
        """Log when a defense action is generated."""
        self._write({
            "event":       "action_created",
            "action_id":   action.get("action_id"),
            "action_type": action.get("action_type"),
            "target":      action.get("target_node"),
            "severity":    action.get("severity"),
            "status":      action.get("status"),
            "confidence":  action.get("confidence"),
            "mitre_ref":   action.get("mitre_ref"),
        })

    def log_approval(self, action_id: str, approver: str, approved: bool) -> None:
        """Log a human approval or rejection."""
        self._write({
            "event":      "human_approval",
            "action_id":  action_id,
            "approver":   approver,
            "decision":   "approved" if approved else "rejected",
        })

    def log_incident_report(self, incident_id: str, report_summary: str) -> None:
        """Log when an LLM incident report is generated."""
        self._write({
            "event":       "incident_report_generated",
            "incident_id": incident_id,
            "summary":     report_summary[:300],
        })

    def log_threat_intel(self, source: str, indicators: list[str]) -> None:
        """Log threat intel feed updates."""
        self._write({
            "event":      "threat_intel_update",
            "source":     source,
            "ioc_count":  len(indicators),
            "sample_iocs": indicators[:10],
        })

    def get_recent_entries(self, limit: int = 100) -> list[dict]:
        """Return the most recent N audit entries."""
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text(encoding="utf-8").strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(entries))
