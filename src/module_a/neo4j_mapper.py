# ============================================================
#  Module A — Neo4j Graph Mapper
#
#  Maps normalized security events onto a Neo4j property graph.
#  Nodes:  User, Machine, Process, File, IPAddress
#  Edges:  LOGGED_IN, ACCESSED, SPAWNED, CONNECTED_TO, ESCALATED
# ============================================================

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from neo4j import GraphDatabase, Driver, Session
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config.settings import get_settings
from src.module_a.event_schemas import (
    BaseEvent, LoginEvent, FileAccessEvent,
    ProcessSpawnEvent, NetworkConnectionEvent,
    PrivilegeEscalationEvent, EventType,
)


# ── Cypher Query Templates ────────────────────────────────────

MERGE_USER = """
MERGE (u:User {name: $username})
  ON CREATE SET u.created_at = $ts, u.risk_score = 0.0
  ON MATCH  SET u.last_seen  = $ts
RETURN u
"""

MERGE_MACHINE = """
MERGE (m:Machine {hostname: $hostname, ip: $ip})
  ON CREATE SET m.created_at = $ts, m.risk_score = 0.0
  ON MATCH  SET m.last_seen  = $ts
RETURN m
"""

MERGE_LOGIN_EDGE = """
MATCH (u:User    {name: $username})
MATCH (src:Machine {hostname: $src_host})
MATCH (dst:Machine {hostname: $dst_host})
MERGE (u)-[r:LOGGED_IN {src_host: $src_host, dst_host: $dst_host}]->(dst)
  ON CREATE SET r.count        = 1,
                r.first_seen   = $ts,
                r.last_seen    = $ts,
                r.auth_method  = $auth_method,
                r.failed_count = $failed,
                r.risk_score   = $risk
  ON MATCH  SET r.count        = r.count + 1,
                r.last_seen    = $ts,
                r.failed_count = r.failed_count + $failed,
                r.risk_score   = CASE WHEN $risk > r.risk_score THEN $risk ELSE r.risk_score END
"""

MERGE_FILE_EDGE = """
MATCH  (u:User    {name: $username})
MATCH  (m:Machine {hostname: $hostname})
MERGE  (f:File    {path: $path, host: $hostname})
  ON CREATE SET f.is_sensitive = $sensitive, f.created_at = $ts
MERGE  (u)-[r:ACCESSED]->(f)
  ON CREATE SET r.count = 1, r.first_seen = $ts, r.last_seen = $ts, r.operation = $op, r.risk_score = $risk
  ON MATCH  SET r.count = r.count + 1, r.last_seen = $ts
"""

MERGE_NETWORK_EDGE = """
MERGE (src:Machine {hostname: $src_host})
MERGE (dst:IPAddress {ip: $dst_ip})
  ON CREATE SET dst.is_internal = $is_internal, dst.created_at = $ts
MERGE (src)-[r:CONNECTED_TO {dst_ip: $dst_ip, port: $port}]->(dst)
  ON CREATE SET r.count      = 1,
                r.bytes_sent = $bytes_sent,
                r.bytes_recv = $bytes_recv,
                r.first_seen = $ts,
                r.last_seen  = $ts,
                r.risk_score = $risk
  ON MATCH  SET r.count      = r.count + 1,
                r.bytes_sent = r.bytes_sent + $bytes_sent,
                r.bytes_recv = r.bytes_recv + $bytes_recv,
                r.last_seen  = $ts
"""

MERGE_PRIVESC_EDGE = """
MATCH (u:User    {name: $username})
MATCH (m:Machine {hostname: $hostname})
MERGE (u)-[r:ESCALATED_ON {hostname: $hostname, method: $method}]->(m)
  ON CREATE SET r.from_role  = $from_role,
                r.to_role    = $to_role,
                r.count      = 1,
                r.first_seen = $ts,
                r.last_seen  = $ts,
                r.risk_score = $risk
  ON MATCH  SET r.count = r.count + 1, r.last_seen = $ts
"""

UPDATE_NODE_RISK = """
MATCH (n {hostname: $hostname})
SET   n.risk_score = CASE WHEN $risk > n.risk_score THEN $risk ELSE n.risk_score END
"""

CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS FOR (u:User)      ON (u.name);
CREATE INDEX IF NOT EXISTS FOR (m:Machine)   ON (m.hostname);
CREATE INDEX IF NOT EXISTS FOR (f:File)      ON (f.path);
CREATE INDEX IF NOT EXISTS FOR (ip:IPAddress) ON (ip.ip);
"""


class Neo4jMapper:
    """
    Thread-safe Neo4j graph mapper.
    Converts security events into graph nodes and relationships.
    """

    def __init__(self):
        self.settings = get_settings()
        self._driver: Optional[Driver] = None

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(min=2, max=30))
    def connect(self) -> None:
        logger.info(f"🔌 Connecting to Neo4j at {self.settings.neo4j_uri}")
        self._driver = GraphDatabase.driver(
            self.settings.neo4j_uri,
            auth=(self.settings.neo4j_user, self.settings.neo4j_password),
            max_connection_lifetime=3600,
            max_connection_pool_size=50,
        )
        self._driver.verify_connectivity()
        self._create_indexes()
        logger.success("✅ Neo4j connection established")

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    @contextlib.contextmanager
    def _session(self):
        with self._driver.session(database="neo4j") as session:
            yield session

    def _create_indexes(self) -> None:
        """Create indexes for fast lookups on startup."""
        with self._session() as s:
            for stmt in CREATE_INDEX.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    s.run(stmt)
        logger.debug("📑 Neo4j indexes verified")

    # ── Risk Score Mapping ────────────────────────────────────

    @staticmethod
    def _severity_to_risk(severity: str) -> float:
        return {
            "info":     0.1,
            "low":      0.3,
            "medium":   0.5,
            "high":     0.8,
            "critical": 1.0,
        }.get(severity.lower(), 0.1)

    # ── Event → Graph Mappings ────────────────────────────────

    def ingest_event(self, event: BaseEvent) -> None:
        """Route an event to the correct graph mapping function."""
        ts = event.timestamp.isoformat()
        risk = self._severity_to_risk(event.severity.value)

        with self._session() as s:
            # Always ensure host node exists
            s.run(MERGE_MACHINE, hostname=event.source_host, ip=event.source_ip, ts=ts)

            dispatcher = {
                EventType.LOGIN:         self._map_login,
                EventType.LOGOUT:        self._map_login,
                EventType.FILE_ACCESS:   self._map_file,
                EventType.FILE_MODIFY:   self._map_file,
                EventType.PROCESS_SPAWN: self._map_process,
                EventType.NETWORK_CONN:  self._map_network,
                EventType.PRIVILEGE_ESC: self._map_privesc,
            }
            fn = dispatcher.get(event.event_type)
            if fn:
                fn(s, event, ts, risk)
            else:
                logger.warning(f"No mapper for event type: {event.event_type}")

    def _map_login(self, s: Session, event: LoginEvent, ts: str, risk: float):
        s.run(MERGE_USER, username=event.username, ts=ts)
        s.run(MERGE_MACHINE, hostname=event.dest_host, ip=event.dest_ip, ts=ts)
        s.run(MERGE_LOGIN_EDGE,
              username=event.username,
              src_host=event.source_host,
              dst_host=event.dest_host,
              ts=ts,
              auth_method=event.auth_method,
              failed=event.failed_attempts,
              risk=risk)

    def _map_file(self, s: Session, event: FileAccessEvent, ts: str, risk: float):
        s.run(MERGE_USER, username=event.username, ts=ts)
        s.run(MERGE_FILE_EDGE,
              username=event.username,
              hostname=event.source_host,
              path=event.file_path,
              sensitive=event.is_sensitive,
              op=event.operation,
              ts=ts,
              risk=risk)

    def _map_process(self, s: Session, event: ProcessSpawnEvent, ts: str, risk: float):
        s.run(MERGE_USER, username=event.username, ts=ts)
        cypher = """
        MATCH (u:User {name: $username})
        MATCH (m:Machine {hostname: $hostname})
        MERGE (p:Process {name: $proc_name, pid: $pid, host: $hostname})
          ON CREATE SET p.parent = $parent, p.cmdline = $cmdline,
                        p.is_signed = $signed, p.created_at = $ts, p.risk_score = $risk
        MERGE (u)-[:SPAWNED]->(p)
        MERGE (m)-[:RUNS]->(p)
        """
        s.run(cypher,
              username=event.username,
              hostname=event.source_host,
              proc_name=event.process_name,
              pid=event.process_id,
              parent=event.parent_process,
              cmdline=event.command_line,
              signed=event.is_signed,
              ts=ts,
              risk=risk)

    def _map_network(self, s: Session, event: NetworkConnectionEvent, ts: str, risk: float):
        s.run(MERGE_NETWORK_EDGE,
              src_host=event.source_host,
              dst_ip=event.dest_ip,
              is_internal=event.is_internal,
              port=event.dest_port,
              bytes_sent=event.bytes_sent,
              bytes_recv=event.bytes_recv,
              ts=ts,
              risk=risk)

    def _map_privesc(self, s: Session, event: PrivilegeEscalationEvent, ts: str, risk: float):
        s.run(MERGE_USER, username=event.username, ts=ts)
        s.run(MERGE_PRIVESC_EDGE,
              username=event.username,
              hostname=event.source_host,
              method=event.method,
              from_role=event.original_role,
              to_role=event.elevated_role,
              ts=ts,
              risk=risk)

    # ── Graph Query Helpers ───────────────────────────────────

    def get_high_risk_nodes(self, threshold: float = 0.6) -> list[dict]:
        """Return all nodes with risk_score above threshold."""
        with self._session() as s:
            result = s.run("""
                MATCH (n)
                WHERE n.risk_score >= $threshold
                RETURN labels(n)[0] AS label,
                       n.hostname  AS hostname,
                       n.name      AS name,
                       n.ip        AS ip,
                       n.risk_score AS risk
                ORDER BY n.risk_score DESC
                LIMIT 50
            """, threshold=threshold)
            return [dict(r) for r in result]

    def get_graph_snapshot(self) -> dict:
        """Fetch nodes + edges for the GNN and dashboard."""
        with self._session() as s:
            nodes_result = s.run("""
                MATCH (n) WHERE n.risk_score IS NOT NULL
                RETURN elementId(n) AS id, labels(n)[0] AS label,
                       COALESCE(n.hostname, n.name, n.ip, n.path) AS name,
                       n.risk_score AS risk_score
                LIMIT 500
            """)
            edges_result = s.run("""
                MATCH (a)-[r]->(b)
                WHERE a.risk_score IS NOT NULL AND b.risk_score IS NOT NULL
                RETURN elementId(a) AS source, elementId(b) AS target,
                       type(r) AS rel_type,
                       COALESCE(r.risk_score, 0.1) AS weight
                LIMIT 1000
            """)
            return {
                "nodes": [dict(r) for r in nodes_result],
                "edges": [dict(r) for r in edges_result],
            }
