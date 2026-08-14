# ============================================================
#  Module A — Kafka Producer (Event Simulator)
#
#  In production: replace the _simulate_* methods with real
#  syslog / Zeek / Wazuh log parsers.
#  In development: runs a realistic simulation of a
#  multi-stage APT attack on a corporate network.
# ============================================================

import json
import random
import time
import ipaddress
from datetime import datetime, timezone
from loguru import logger
from confluent_kafka import Producer, KafkaException

from src.config.settings import get_settings
from src.module_a.event_schemas import (
    LoginEvent, FileAccessEvent, ProcessSpawnEvent,
    NetworkConnectionEvent, PrivilegeEscalationEvent,
    EventType, Severity, AuthResult,
)


# ── Simulated Network Topology ───────────────────────────────

HOSTS = {
    "WS-001": "10.0.1.10",
    "WS-002": "10.0.1.11",
    "WS-003": "10.0.1.12",
    "SRV-DC1": "10.0.2.10",     # Domain Controller
    "SRV-FILE": "10.0.2.11",    # File Server
    "SRV-DB": "10.0.2.12",      # Database Server
    "SRV-WEB": "10.0.2.13",     # Web Server
}

USERS = ["alice", "bob", "charlie", "dave", "svc-backup", "admin"]
SENSITIVE_PATHS = ["/etc/shadow", "/etc/passwd", "C:\\Windows\\NTDS\\ntds.dit",
                   "C:\\Windows\\System32\\config\\SAM", "/var/lib/mysql"]

# Simulated APT attack chain (mimics real lateral movement)
APT_CHAIN = [
    ("WS-001", "alice",   EventType.LOGIN,       Severity.INFO),
    ("WS-001", "alice",   EventType.PROCESS_SPAWN, Severity.LOW),
    ("WS-001", "alice",   EventType.NETWORK_CONN,  Severity.MEDIUM),
    ("WS-002", "alice",   EventType.LOGIN,          Severity.MEDIUM),
    ("WS-002", "alice",   EventType.FILE_ACCESS,    Severity.HIGH),
    ("SRV-DC1","alice",   EventType.LOGIN,          Severity.HIGH),
    ("SRV-DC1","alice",   EventType.PRIVILEGE_ESC,  Severity.CRITICAL),
    ("SRV-DB", "admin",   EventType.LOGIN,          Severity.CRITICAL),
]


class ThreatHunterProducer:
    """
    Kafka producer that publishes security events to the raw-events topic.
    Supports both simulation mode and real log ingestion.
    """

    def __init__(self):
        self.settings = get_settings()
        self._producer = self._create_producer()

    def _create_producer(self) -> Producer:
        conf = {
            "bootstrap.servers": self.settings.kafka_bootstrap_servers,
            "client.id": "threat-hunter-producer",
            "acks": "all",
            "retries": 5,
            "retry.backoff.ms": 300,
            "compression.type": "snappy",
        }
        logger.info(f"🔌 Connecting producer to Kafka: {self.settings.kafka_bootstrap_servers}")
        return Producer(conf)

    def _delivery_report(self, err, msg):
        if err:
            logger.error(f"❌ Kafka delivery failed: {err}")
        else:
            logger.debug(f"✅ Event delivered → topic={msg.topic()} partition={msg.partition()} offset={msg.offset()}")

    def publish(self, event, topic: str = None) -> None:
        """Serialize and publish a single event to Kafka."""
        topic = topic or self.settings.kafka_topic_raw
        payload = event.to_kafka_payload()
        self._producer.produce(
            topic=topic,
            key=event.source_host.encode("utf-8"),
            value=payload.encode("utf-8"),
            callback=self._delivery_report,
        )
        self._producer.poll(0)

    def flush(self):
        self._producer.flush(timeout=10)

    # ── Event Generators ─────────────────────────────────────

    def _make_login(self, host: str, user: str, severity: Severity) -> LoginEvent:
        ip = HOSTS.get(host, "10.0.99.99")
        dest_host = random.choice(list(HOSTS.keys()))
        failed = random.randint(0, 5) if severity != Severity.INFO else 0
        return LoginEvent(
            source_ip=ip,
            source_host=host,
            username=user,
            dest_host=dest_host,
            dest_ip=HOSTS.get(dest_host, "10.0.99.1"),
            auth_method=random.choice(["kerberos", "ntlm", "password"]),
            auth_result=AuthResult.FAILURE if failed > 3 else AuthResult.SUCCESS,
            failed_attempts=failed,
            severity=severity,
        )

    def _make_file_access(self, host: str, user: str, severity: Severity) -> FileAccessEvent:
        is_sensitive = severity in (Severity.HIGH, Severity.CRITICAL)
        path = random.choice(SENSITIVE_PATHS) if is_sensitive else f"/home/{user}/documents/report.pdf"
        return FileAccessEvent(
            source_ip=HOSTS.get(host, "10.0.1.1"),
            source_host=host,
            username=user,
            file_path=path,
            operation=random.choice(["read", "write", "read"]),
            is_sensitive=is_sensitive,
            severity=severity,
        )

    def _make_process(self, host: str, user: str, severity: Severity) -> ProcessSpawnEvent:
        suspicious = severity in (Severity.HIGH, Severity.CRITICAL)
        proc = ("mimikatz.exe" if suspicious else random.choice(["chrome.exe", "explorer.exe", "python.exe"]))
        return ProcessSpawnEvent(
            source_ip=HOSTS.get(host, "10.0.1.1"),
            source_host=host,
            username=user,
            process_name=proc,
            process_id=random.randint(1000, 9999),
            parent_process="cmd.exe" if suspicious else "explorer.exe",
            command_line=f"{proc} --dump" if suspicious else f"{proc}",
            is_signed=not suspicious,
            severity=severity,
        )

    def _make_network_conn(self, host: str, user: str, severity: Severity) -> NetworkConnectionEvent:
        external = severity == Severity.CRITICAL
        return NetworkConnectionEvent(
            source_ip=HOSTS.get(host, "10.0.1.1"),
            source_host=host,
            dest_ip="185.220.101.47" if external else random.choice(list(HOSTS.values())),
            dest_port=random.choice([4444, 443, 8080, 22]) if external else 445,
            is_internal=not external,
            bytes_sent=random.randint(500, 50000),
            bytes_recv=random.randint(200, 5000),
            severity=severity,
        )

    def _make_privesc(self, host: str, user: str, severity: Severity) -> PrivilegeEscalationEvent:
        return PrivilegeEscalationEvent(
            source_ip=HOSTS.get(host, "10.0.2.10"),
            source_host=host,
            username=user,
            original_role="user",
            elevated_role="SYSTEM" if severity == Severity.CRITICAL else "Administrator",
            method=random.choice(["token_impersonation", "exploit", "runas"]),
            severity=severity,
        )

    # ── Main Simulation Loop ──────────────────────────────────

    def run_simulation(self, mode: str = "apt", interval: float = 2.0):
        """
        Run the event simulator.

        mode="apt"    → Replays the realistic APT attack chain
        mode="random" → Random benign + suspicious mix
        """
        logger.info(f"🚀 Starting Kafka producer simulation [mode={mode}]")

        if mode == "apt":
            self._run_apt_simulation(interval)
        else:
            self._run_random_simulation(interval)

    def _run_apt_simulation(self, interval: float = 0.3):
        """Replay a realistic multi-stage APT attack."""
        logger.warning("⚠️  Starting APT attack simulation — for lab use only!")
        from src.module_a.neo4j_mapper import Neo4jMapper
        neo4j = Neo4jMapper()
        try:
            neo4j.connect()
        except Exception as e:
            logger.warning(f"Neo4j direct connect warning: {e}")
            neo4j = None

        for i, (host, user, event_type, severity) in enumerate(APT_CHAIN):
            event = self._generate_event(host, user, event_type, severity)
            logger.info(f"[Step {i+1}/{len(APT_CHAIN)}] {event_type.value} | host={host} | user={user} | severity={severity.value}")
            self.publish(event)
            if neo4j:
                try:
                    neo4j.ingest_event(event)
                except Exception as e:
                    logger.error(f"Neo4j ingest error: {e}")
            time.sleep(interval)

        if neo4j:
            neo4j.close()

        self.flush()
        logger.success("✅ APT simulation complete")

    def _run_random_simulation(self, interval: float):
        """Continuous random event stream — runs indefinitely."""
        benign_ratio = 0.85  # 85% normal, 15% suspicious
        try:
            while True:
                host = random.choice(list(HOSTS.keys()))
                user = random.choice(USERS)
                is_suspicious = random.random() > benign_ratio
                severity = random.choice([Severity.MEDIUM, Severity.HIGH]) if is_suspicious else Severity.INFO
                event_type = random.choice(list(EventType)[:5])
                event = self._generate_event(host, user, event_type, severity)
                self.publish(event)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("🛑 Producer stopped by user")
            self.flush()

    def _generate_event(self, host, user, event_type, severity):
        generators = {
            EventType.LOGIN:         self._make_login,
            EventType.LOGOUT:        self._make_login,
            EventType.FILE_ACCESS:   self._make_file_access,
            EventType.FILE_MODIFY:   self._make_file_access,
            EventType.PROCESS_SPAWN: self._make_process,
            EventType.NETWORK_CONN:  self._make_network_conn,
            EventType.PRIVILEGE_ESC: self._make_privesc,
        }
        fn = generators.get(event_type, self._make_login)
        return fn(host, user, severity)


# ── Entry point ───────────────────────────────────────────────

def run_simulation(mode: str = "apt", interval: float = 0.3):
    """Module-level helper to instantiate producer and run simulation."""
    producer = ThreatHunterProducer()
    producer.run_simulation(mode=mode, interval=interval)


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "random"
    run_simulation(mode=mode, interval=1.0)

