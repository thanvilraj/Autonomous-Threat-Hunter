# ============================================================
#  Module C — Threat Intelligence Feed
#
#  Polls AlienVault OTX and NVD (CVE) for live IOC data.
#  Enriches alerts with zero-day and known-bad indicator context.
# ============================================================

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp
from loguru import logger

from src.config.settings import get_settings
from src.module_b.audit_logger import AuditLogger


class ThreatIntelFeed:
    """
    Real-time threat intelligence aggregator.
    Sources: AlienVault OTX, NVD CVE database.
    """

    OTX_BASE = "https://otx.alienvault.com/api/v1"
    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, audit_logger: AuditLogger):
        self.settings    = get_settings()
        self.audit        = audit_logger
        self._ioc_cache: dict[str, dict] = {}   # ip/domain → threat info
        self._last_fetch: Optional[datetime] = None

    async def enrich_ip(self, ip: str) -> Optional[str]:
        """
        Check if an IP is a known malicious indicator.
        Returns a plain-text enrichment string or None.
        """
        if ip in self._ioc_cache:
            data = self._ioc_cache[ip]
            return (
                f"⚠️ KNOWN MALICIOUS IP: {ip}\n"
                f"   Source: {data.get('source')}\n"
                f"   Reputation: {data.get('reputation', 'Unknown')}\n"
                f"   Associated malware: {data.get('malware', 'Unknown')}\n"
                f"   Country: {data.get('country', 'Unknown')}"
            )
        return None

    async def fetch_otx_pulses(self) -> list[dict]:
        """Fetch recent threat pulses from AlienVault OTX."""
        if not self.settings.otx_api_key:
            logger.warning("⚠️  OTX API key not configured — skipping OTX feed")
            return []

        headers = {"X-OTX-API-KEY": self.settings.otx_api_key}
        since   = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        url     = f"{self.OTX_BASE}/pulses/subscribed?modified_since={since}&limit=20"

        try:
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        pulses = data.get("results", [])
                        logger.info(f"📡 OTX: {len(pulses)} new threat pulses fetched")
                        self._index_otx_indicators(pulses)
                        return pulses
                    else:
                        logger.error(f"OTX API error: {resp.status}")
        except Exception as e:
            logger.error(f"OTX fetch failed: {e}")
        return []

    def _index_otx_indicators(self, pulses: list[dict]) -> None:
        """Extract and cache IP/domain IOCs from OTX pulses."""
        count = 0
        for pulse in pulses:
            malware = pulse.get("tags", ["unknown"])[0] if pulse.get("tags") else "unknown"
            for indicator in pulse.get("indicators", []):
                if indicator.get("type") in ("IPv4", "domain", "hostname"):
                    ioc = indicator.get("indicator", "")
                    if ioc:
                        self._ioc_cache[ioc] = {
                            "source":     "AlienVault OTX",
                            "reputation": "Malicious",
                            "malware":    malware,
                            "country":    indicator.get("country_name", "Unknown"),
                            "pulse_name": pulse.get("name", ""),
                        }
                        count += 1
        logger.info(f"🗂  Cached {count} IOC indicators from OTX")
        self.audit.log_threat_intel("AlienVault OTX", list(self._ioc_cache.keys())[:10])

    async def fetch_recent_cves(self, keyword: str = "remote code execution") -> list[dict]:
        """Fetch recent critical CVEs from NVD."""
        params = {
            "keywordSearch":    keyword,
            "cvssV3Severity":   "CRITICAL",
            "resultsPerPage":   5,
            "pubStartDate":     (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":       datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999"),
        }
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                async with session.get(self.NVD_BASE, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        logger.info(f"📡 NVD: {len(vulns)} critical CVEs fetched")
                        return [self._format_cve(v) for v in vulns]
                    else:
                        logger.error(f"NVD API error: {resp.status}")
        except Exception as e:
            logger.error(f"NVD fetch failed: {e}")
        return []

    @staticmethod
    def _format_cve(vuln: dict) -> dict:
        cve  = vuln.get("cve", {})
        cve_id   = cve.get("id", "CVE-UNKNOWN")
        desc     = cve.get("descriptions", [{}])[0].get("value", "")[:300]
        metrics  = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
        score    = metrics.get("cvssData", {}).get("baseScore", 0)
        return {
            "cve_id":      cve_id,
            "description": desc,
            "cvss_score":  score,
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    async def run_polling_loop(self) -> None:
        """Background loop that refreshes threat intel every N minutes."""
        interval = self.settings.threat_intel_poll_min * 60
        logger.info(f"⏱  Threat intel polling loop started (every {self.settings.threat_intel_poll_min} min)")
        while True:
            try:
                await self.fetch_otx_pulses()
                self._last_fetch = datetime.now(timezone.utc)
            except Exception as e:
                logger.error(f"Threat intel poll failed: {e}")
            await asyncio.sleep(interval)

    def get_intel_summary(self) -> dict:
        return {
            "cached_iocs": len(self._ioc_cache),
            "last_fetch":  self._last_fetch.isoformat() if self._last_fetch else None,
            "sources":     ["AlienVault OTX", "NVD CVE"],
        }
