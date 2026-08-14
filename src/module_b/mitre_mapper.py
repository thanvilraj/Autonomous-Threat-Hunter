# ============================================================
#  Module B — MITRE ATT&CK Mapper
#
#  Maps GNN-detected threat patterns to MITRE ATT&CK tactics
#  and techniques using a local STIX JSON knowledge base.
#  Falls back to heuristic rules when STIX is unavailable.
# ============================================================

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Optional

from loguru import logger


# ── Local MITRE knowledge base (heuristic rules) ─────────────
# In production: load from data/mitre/enterprise-attack.json
# Download: https://github.com/mitre/cti

HEURISTIC_RULES: list[dict] = [
    {
        "id":        "T1078",
        "name":      "Valid Accounts",
        "tactic":    "Initial Access / Persistence / Privilege Escalation",
        "triggers":  ["login", "failed_attempts > 3", "auth_method=ntlm"],
        "severity":  "high",
        "mitigations": [
            "Enforce MFA on all accounts",
            "Review privileged account usage",
            "Enable account lockout policies",
        ],
    },
    {
        "id":        "T1021",
        "name":      "Remote Services",
        "tactic":    "Lateral Movement",
        "triggers":  ["network_connection", "is_internal=True", "port=445"],
        "severity":  "high",
        "mitigations": [
            "Restrict SMB/RDP to necessary hosts only",
            "Segment network to limit lateral movement",
            "Monitor for unusual remote service usage",
        ],
    },
    {
        "id":        "T1003",
        "name":      "OS Credential Dumping",
        "tactic":    "Credential Access",
        "triggers":  ["process_spawn", "proc_name=mimikatz", "is_signed=False"],
        "severity":  "critical",
        "mitigations": [
            "Enable Credential Guard on Windows systems",
            "Restrict access to LSASS process",
            "Alert on unsigned binary execution",
        ],
    },
    {
        "id":        "T1548",
        "name":      "Abuse Elevation Control Mechanism",
        "tactic":    "Privilege Escalation",
        "triggers":  ["privilege_escalation", "method=token_impersonation"],
        "severity":  "critical",
        "mitigations": [
            "Audit privilege escalation events",
            "Apply least-privilege access model",
            "Monitor for token manipulation",
        ],
    },
    {
        "id":        "T1005",
        "name":      "Data from Local System",
        "tactic":    "Collection",
        "triggers":  ["file_access", "is_sensitive=True"],
        "severity":  "high",
        "mitigations": [
            "Implement data loss prevention (DLP)",
            "Audit access to sensitive file paths",
            "Enable file integrity monitoring",
        ],
    },
    {
        "id":        "T1041",
        "name":      "Exfiltration Over C2 Channel",
        "tactic":    "Exfiltration",
        "triggers":  ["network_connection", "is_internal=False", "bytes_sent > 10000"],
        "severity":  "critical",
        "mitigations": [
            "Block unexpected external connections at firewall",
            "Inspect outbound traffic with SSL inspection",
            "Alert on large data transfers to unknown IPs",
        ],
    },
    {
        "id":        "T1057",
        "name":      "Process Discovery",
        "tactic":    "Discovery",
        "triggers":  ["process_spawn", "command_line contains 'ps' or 'tasklist'"],
        "severity":  "medium",
        "mitigations": [
            "Audit process enumeration commands",
            "Monitor command line arguments",
        ],
    },
]

# Tactics in MITRE ATT&CK kill-chain order
KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


class MitreMapper:
    """
    Maps detected threat nodes to MITRE ATT&CK framework entries.
    Uses heuristic pattern matching + optional STIX JSON lookup.
    """

    STIX_PATH = "data/mitre/enterprise-attack.json"

    def __init__(self):
        self._stix_loaded = False
        self._techniques: dict[str, dict] = {}
        self._load_stix()

    def _load_stix(self) -> None:
        """Load MITRE ATT&CK STIX bundle if available."""
        if not os.path.exists(self.STIX_PATH):
            logger.warning(
                f"⚠️  MITRE STIX not found at {self.STIX_PATH}. "
                "Using heuristic rules. Download from: "
                "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
            )
            return

        try:
            with open(self.STIX_PATH) as f:
                bundle = json.load(f)

            for obj in bundle.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ext_refs = obj.get("external_references", [])
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id", "")
                            self._techniques[tech_id] = {
                                "id":          tech_id,
                                "name":        obj.get("name", ""),
                                "description": obj.get("description", "")[:500],
                                "tactic":      ", ".join(
                                    p.get("phase_name", "").replace("-", " ").title()
                                    for p in obj.get("kill_chain_phases", [])
                                ),
                                "url": ref.get("url", ""),
                            }

            self._stix_loaded = True
            logger.success(f"✅ MITRE ATT&CK STIX loaded: {len(self._techniques)} techniques")

        except Exception as e:
            logger.error(f"Failed to load MITRE STIX: {e}")

    def map_node_to_attack(self, node: dict) -> dict:
        """
        Given a threat node dict from the GNN, return relevant MITRE info.

        Matching is based on node type + risk score heuristics.
        Returns the best-matching technique entry.
        """
        score = node.get("threat_score", 0.0)
        label = node.get("node_label", "Unknown")
        name  = node.get("node_name", "")

        # Select rules most relevant to the node type
        candidate_rules = self._select_rules(label, score)

        if not candidate_rules:
            return self._unknown_technique()

        # Pick the highest-severity matching rule
        best = sorted(
            candidate_rules,
            key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(r["severity"], 0),
            reverse=True,
        )[0]

        # Enrich with STIX data if available
        stix_entry = self._techniques.get(best["id"], {})

        return {
            "technique_id":   best["id"],
            "technique_name": best["name"],
            "tactic":         best["tactic"],
            "severity":       best["severity"],
            "mitigations":    best["mitigations"],
            "description":    stix_entry.get("description", "See MITRE ATT&CK for details"),
            "url":            stix_entry.get("url", f"https://attack.mitre.org/techniques/{best['id']}"),
            "kill_chain_position": self._get_chain_position(best["tactic"]),
        }

    def _select_rules(self, node_label: str, threat_score: float) -> list[dict]:
        """Heuristic: pick rules based on node type."""
        label_map = {
            "User":      ["T1078", "T1548"],
            "Machine":   ["T1021", "T1003", "T1041"],
            "Process":   ["T1003", "T1057"],
            "File":      ["T1005"],
            "IPAddress": ["T1041"],
        }
        relevant_ids = label_map.get(node_label, [r["id"] for r in HEURISTIC_RULES])
        return [r for r in HEURISTIC_RULES if r["id"] in relevant_ids]

    def _get_chain_position(self, tactic: str) -> int:
        """Return the MITRE kill-chain stage index for ordering."""
        for i, stage in enumerate(KILL_CHAIN_ORDER):
            if stage.lower() in tactic.lower():
                return i
        return 99

    @staticmethod
    def _unknown_technique() -> dict:
        return {
            "technique_id":   "T0000",
            "technique_name": "Unknown Technique",
            "tactic":         "Unknown",
            "severity":       "medium",
            "mitigations":    ["Investigate the flagged host manually"],
            "description":    "No MITRE technique matched for this node",
            "url":            "https://attack.mitre.org",
            "kill_chain_position": 99,
        }

    def get_all_techniques(self) -> list[dict]:
        """Return all loaded STIX techniques (for search/reference UI)."""
        if self._stix_loaded:
            return list(self._techniques.values())
        return HEURISTIC_RULES
