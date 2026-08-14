# ============================================================
#  Module C — LangChain Incident Reporter
#
#  Converts raw threat data into plain-English incident reports
#  using a local Ollama LLM (or OpenAI as fallback).
# ============================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

try:
    from langchain_core.prompts import ChatPromptTemplate
except ImportError:
    from langchain.prompts import ChatPromptTemplate
try:
    from langchain_core.output_parsers import StrOutputParser
except ImportError:
    from langchain.schema.output_parser import StrOutputParser
from loguru import logger

from src.config.settings import get_settings


# ── Prompt Templates ─────────────────────────────────────────

INCIDENT_REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior cybersecurity analyst writing incident reports for a Security Operations Center (SOC).
Your reports must be:
- Written in clear, professional English that non-technical managers can understand
- Structured with: Executive Summary, Technical Details, Timeline, Impact Assessment, and Recommended Actions
- Factual and based only on the provided data — do not speculate beyond the evidence
- Concise: Executive Summary must be under 100 words

Always start with the severity badge: [CRITICAL] / [HIGH] / [MEDIUM] / [LOW]"""),

    ("human", """Generate an incident report for the following threat detection:

THREAT NODE: {node_name} ({node_type})
THREAT SCORE: {threat_score} / 1.0
MITRE ATT&CK TECHNIQUE: {technique_id} — {technique_name}
TACTIC: {tactic}
DETECTION TIME: {detection_time}

TRIGGERED INDICATORS:
{indicators}

RECOMMENDED DEFENSE ACTIONS:
{defense_actions}

THREAT INTEL CONTEXT:
{threat_intel}

Write the full incident report:""")
])

EXECUTIVE_BRIEF_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are a cybersecurity expert. Summarise the following incident in 2 sentences for a C-level executive. Be clear, concise, and avoid jargon."),
    ("human", "{incident_summary}"),
])


class LangChainReporter:
    """
    Generates plain-English incident reports from threat data.
    Supports Ollama (local, free) and OpenAI (cloud) providers.
    """

    def __init__(self):
        self.settings = get_settings()
        self._llm     = self._init_llm()
        self._chain   = INCIDENT_REPORT_PROMPT | self._llm | StrOutputParser()
        self._brief_chain = EXECUTIVE_BRIEF_PROMPT | self._llm | StrOutputParser()
        logger.info(f"🤖 LLM Reporter initialized: provider={self.settings.llm_provider}")

    def _init_llm(self):
        """Initialize the correct LLM based on settings."""
        if self.settings.llm_provider == "openai" and self.settings.openai_api_key:
            from langchain_openai import ChatOpenAI
            logger.info(f"Using OpenAI: {self.settings.openai_model}")
            return ChatOpenAI(
                model=self.settings.openai_model,
                api_key=self.settings.openai_api_key,
                temperature=0.2,   # Low temp for factual reports
                max_tokens=2000,
            )
        else:
            from langchain_ollama import ChatOllama
            logger.info(f"Using Ollama: {self.settings.ollama_model} @ {self.settings.ollama_base_url}")
            return ChatOllama(
                model=self.settings.ollama_model,
                base_url=self.settings.ollama_base_url,
                temperature=0.2,
                num_predict=2000,
            )

    def generate_incident_report(
        self,
        node:          dict,
        mitre_info:    dict,
        defense_recs:  list[dict],
        threat_intel:  Optional[str] = None,
    ) -> dict:
        """
        Generate a full incident report for a threat node.

        Returns:
          {incident_id, report_text, executive_brief, severity, generated_at}
        """
        incident_id    = f"INC-{uuid.uuid4().hex[:8].upper()}"
        detection_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Format defense recommendations
        actions_text = "\n".join(
            f"  [{i+1}] [{rec['severity'].upper()}] {rec['description']}"
            f"{' ⚠️ REQUIRES HUMAN APPROVAL' if rec['severity'] in ('high', 'critical') else ''}"
            for i, rec in enumerate(defense_recs[:5])
        ) or "No specific actions generated."

        # Format indicators
        indicators_text = self._format_indicators(node, mitre_info)

        logger.info(f"📝 Generating incident report {incident_id} via {self.settings.llm_provider}...")

        try:
            report_text = self._chain.invoke({
                "node_name":      node.get("node_name", "Unknown"),
                "node_type":      node.get("node_label", "Unknown"),
                "threat_score":   f"{node.get('threat_score', 0):.2%}",
                "technique_id":   mitre_info.get("technique_id", "N/A"),
                "technique_name": mitre_info.get("technique_name", "Unknown"),
                "tactic":         mitre_info.get("tactic", "Unknown"),
                "detection_time": detection_time,
                "indicators":     indicators_text,
                "defense_actions": actions_text,
                "threat_intel":   threat_intel or "No additional threat intelligence available.",
            })

            # Generate executive brief
            executive_brief = self._brief_chain.invoke({"incident_summary": report_text[:1000]})

        except Exception as e:
            logger.error(f"❌ LLM generation failed: {e}")
            report_text     = self._fallback_report(node, mitre_info, defense_recs)
            executive_brief = f"Threat detected on {node.get('node_name')}. Analyst review required."

        result = {
            "incident_id":     incident_id,
            "report_text":     report_text,
            "executive_brief": executive_brief,
            "severity":        mitre_info.get("severity", "medium").upper(),
            "node_name":       node.get("node_name"),
            "technique_id":    mitre_info.get("technique_id"),
            "generated_at":    datetime.now(timezone.utc).isoformat(),
        }

        logger.success(f"✅ Incident report generated: {incident_id}")
        return result

    @staticmethod
    def _format_indicators(node: dict, mitre_info: dict) -> str:
        indicators = [
            f"  • Node type: {node.get('node_label', 'Unknown')}",
            f"  • Threat score: {node.get('threat_score', 0):.2%} (threshold: 65%)",
            f"  • MITRE tactic: {mitre_info.get('tactic', 'Unknown')}",
            f"  • Kill chain stage: {mitre_info.get('kill_chain_position', 'Unknown')}",
        ]
        return "\n".join(indicators)

    @staticmethod
    def _fallback_report(node: dict, mitre_info: dict, defense_recs: list[dict]) -> str:
        """Plain-text fallback if LLM is unavailable."""
        return (
            f"[{mitre_info.get('severity', 'MEDIUM').upper()}] THREAT DETECTED\n\n"
            f"Target: {node.get('node_name', 'Unknown')} ({node.get('node_label', 'Unknown')})\n"
            f"Score: {node.get('threat_score', 0):.2%}\n"
            f"Technique: {mitre_info.get('technique_id')} — {mitre_info.get('technique_name')}\n"
            f"Tactic: {mitre_info.get('tactic')}\n\n"
            f"Recommended Actions:\n"
            + "\n".join(f"  • {r['description']}" for r in defense_recs[:3])
        )
