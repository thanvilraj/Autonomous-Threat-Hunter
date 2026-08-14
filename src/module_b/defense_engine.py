# ============================================================
#  Module B — Defense Engine
#
#  Generates tiered defense recommendations.
#  RESPONSIBLE AI: HIGH-severity actions require human approval.
#  The system can NEVER execute destructive actions autonomously.
# ============================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import redis
import json
from loguru import logger

from src.config.settings import get_settings


class ActionSeverity(str, Enum):
    LOW      = "low"       # Log + alert only (auto-executed)
    MEDIUM   = "medium"    # Isolate process / block port (auto-executed)
    HIGH     = "high"      # Network quarantine (REQUIRES human approval)
    CRITICAL = "critical"  # System lockdown (REQUIRES human approval)


class ActionStatus(str, Enum):
    PENDING  = "pending"    # Awaiting human approval
    APPROVED = "approved"   # Human approved, ready to execute
    REJECTED = "rejected"   # Human rejected
    EXECUTED = "executed"   # Carried out
    AUTO     = "auto"       # Automatically executed (LOW/MEDIUM only)


# ── Defense Action Definition ─────────────────────────────────

class DefenseAction:
    def __init__(
        self,
        action_type:  str,
        target_node:  str,
        target_ip:    Optional[str],
        description:  str,
        severity:     ActionSeverity,
        mitre_ref:    str,
        confidence:   float,
        command_hint: str = "",
    ):
        self.action_id    = str(uuid.uuid4())
        self.action_type  = action_type
        self.target_node  = target_node
        self.target_ip    = target_ip
        self.description  = description
        self.severity     = severity
        self.mitre_ref    = mitre_ref
        self.confidence   = confidence
        self.command_hint = command_hint
        self.status       = ActionStatus.PENDING
        self.created_at   = datetime.now(timezone.utc).isoformat()
        self.approved_by  = None
        self.executed_at  = None

    def to_dict(self) -> dict:
        return {
            "action_id":    self.action_id,
            "action_type":  self.action_type,
            "target_node":  self.target_node,
            "target_ip":    self.target_ip,
            "description":  self.description,
            "severity":     self.severity.value,
            "mitre_ref":    self.mitre_ref,
            "confidence":   self.confidence,
            "command_hint": self.command_hint,
            "status":       self.status.value,
            "created_at":   self.created_at,
            "approved_by":  self.approved_by,
            "executed_at":  self.executed_at,
        }


# ── Defense Engine ────────────────────────────────────────────

class DefenseEngine:
    """
    Generates defense recommendations based on GNN predictions
    and MITRE ATT&CK mappings.

    RESPONSIBLE AI RULES:
      • LOW / MEDIUM → auto-executed (safe, reversible)
      • HIGH / CRITICAL → queued for human approval
      • No action modifies production systems without logging
      • All decisions include confidence score + MITRE reference
    """

    def __init__(self):
        self.settings = get_settings()
        self._redis: Optional[redis.Redis] = None
        self._connect_redis()

    def _connect_redis(self) -> None:
        try:
            self._redis = redis.Redis(
                host=self.settings.redis_host,
                port=self.settings.redis_port,
                password=self.settings.redis_password,
                decode_responses=True,
                socket_timeout=5,
            )
            self._redis.ping()
            logger.info("✅ Defense engine connected to Redis approval queue")
        except Exception as e:
            logger.warning(f"⚠️  Redis unavailable — approval queue disabled: {e}")
            self._redis = None

    def generate_recommendations(
        self,
        node: dict,
        mitre_info: dict,
    ) -> list[dict]:
        """
        Produce a ranked list of defense actions for a threat node.
        """
        score      = node.get("threat_score", 0.0)
        node_label = node.get("node_label", "Unknown")
        node_name  = node.get("node_name", "unknown")
        target_ip  = None  # enriched later from Neo4j
        mitre_ref  = mitre_info.get("technique_id", "T0000")
        tactic     = mitre_info.get("tactic", "Unknown")

        actions: list[DefenseAction] = []

        # ── Always: Alert ─────────────────────────────────────
        actions.append(DefenseAction(
            action_type  = "alert",
            target_node  = node_name,
            target_ip    = target_ip,
            description  = (
                f"Threat detected on {node_label} '{node_name}' "
                f"(score={score:.2f}, tactic={tactic}). "
                "Analyst review recommended."
            ),
            severity     = ActionSeverity.LOW,
            mitre_ref    = mitre_ref,
            confidence   = score,
            command_hint = "",
        ))

        # ── Medium: Process / Session Termination ─────────────
        if score >= 0.55 and node_label in ("Process", "User"):
            actions.append(DefenseAction(
                action_type  = "terminate_session",
                target_node  = node_name,
                target_ip    = target_ip,
                description  = f"Terminate suspicious session/process '{node_name}'",
                severity     = ActionSeverity.MEDIUM,
                mitre_ref    = mitre_ref,
                confidence   = score,
                command_hint = f"pkill -u {node_name} OR taskkill /PID <pid> /F",
            ))

        # ── Medium: Block Port / Service ─────────────────────
        if score >= 0.60 and node_label == "IPAddress":
            actions.append(DefenseAction(
                action_type  = "block_port",
                target_node  = node_name,
                target_ip    = node_name,
                description  = f"Block outbound traffic to suspicious IP {node_name}",
                severity     = ActionSeverity.MEDIUM,
                mitre_ref    = mitre_ref,
                confidence   = score,
                command_hint = f"iptables -A OUTPUT -d {node_name} -j DROP",
            ))

        # ── High: Network Quarantine ──────────────────────────
        if score >= 0.75 and node_label == "Machine":
            actions.append(DefenseAction(
                action_type  = "network_quarantine",
                target_node  = node_name,
                target_ip    = target_ip,
                description  = (
                    f"Quarantine host '{node_name}' from network. "
                    "This will cut all network access to/from this machine."
                ),
                severity     = ActionSeverity.HIGH,
                mitre_ref    = mitre_ref,
                confidence   = score,
                command_hint = f"# Firewall rule: deny all traffic from/to {node_name}",
            ))

        # ── Critical: Account Disable ─────────────────────────
        if score >= 0.85 and node_label == "User":
            actions.append(DefenseAction(
                action_type  = "disable_account",
                target_node  = node_name,
                target_ip    = None,
                description  = (
                    f"Disable user account '{node_name}' immediately. "
                    "This will prevent all further logins for this user."
                ),
                severity     = ActionSeverity.CRITICAL,
                mitre_ref    = mitre_ref,
                confidence   = score,
                command_hint = f"usermod -L {node_name} OR Disable-ADAccount -Identity {node_name}",
            ))

        # ── Route actions to approval queue or auto-execute ───
        results = []
        for action in actions:
            self._route_action(action)
            results.append(action.to_dict())

        return results

    def _route_action(self, action: DefenseAction) -> None:
        """
        Route action based on severity:
          LOW/MEDIUM → mark as AUTO (safe to execute)
          HIGH/CRITICAL → push to human approval queue in Redis
        """
        needs_approval = action.severity in (ActionSeverity.HIGH, ActionSeverity.CRITICAL)

        if needs_approval and self.settings.require_human_approval_for_high:
            action.status = ActionStatus.PENDING
            self._push_to_approval_queue(action)
            logger.warning(
                f"🔒 Action queued for human approval: "
                f"[{action.severity.value.upper()}] {action.action_type} → {action.target_node}"
            )
        else:
            action.status = ActionStatus.AUTO
            logger.info(
                f"✅ Auto-action: [{action.severity.value.upper()}] "
                f"{action.action_type} → {action.target_node}"
            )

    def _push_to_approval_queue(self, action: DefenseAction) -> None:
        """Store pending action in Redis for analyst to approve/reject."""
        if not self._redis:
            logger.warning("Redis unavailable — action approval not persisted")
            return
        key = f"approval:{action.action_id}"
        self._redis.setex(key, 86400, json.dumps(action.to_dict()))  # TTL: 24h
        self._redis.lpush("approval_queue", action.action_id)

    def approve_action(self, action_id: str, approver: str) -> dict:
        """Human approves a pending action."""
        return self._update_action_status(action_id, ActionStatus.APPROVED, approver)

    def reject_action(self, action_id: str, approver: str) -> dict:
        """Human rejects a pending action."""
        return self._update_action_status(action_id, ActionStatus.REJECTED, approver)

    def _update_action_status(self, action_id: str, status: ActionStatus, approver: str) -> dict:
        if not self._redis:
            return {"error": "Redis not available"}
        key = f"approval:{action_id}"
        raw = self._redis.get(key)
        if not raw:
            return {"error": f"Action {action_id} not found"}
        data = json.loads(raw)
        data["status"]      = status.value
        data["approved_by"] = approver
        data["executed_at"] = datetime.now(timezone.utc).isoformat()
        self._redis.setex(key, 86400, json.dumps(data))
        logger.info(f"{'✅' if status == ActionStatus.APPROVED else '❌'} Action {action_id} {status.value} by {approver}")
        return data

    def get_pending_actions(self) -> list[dict]:
        """Return all actions awaiting human approval."""
        if not self._redis:
            return []
        queue = self._redis.lrange("approval_queue", 0, -1)
        actions = []
        for action_id in queue:
            raw = self._redis.get(f"approval:{action_id}")
            if raw:
                data = json.loads(raw)
                if data.get("status") == ActionStatus.PENDING.value:
                    actions.append(data)
        return actions
