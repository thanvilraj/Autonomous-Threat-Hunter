# ============================================================
#  Tests — Module A
# ============================================================

import pytest
from datetime import datetime
from src.module_a.event_schemas import (
    LoginEvent, FileAccessEvent, ProcessSpawnEvent,
    NetworkConnectionEvent, EventType, Severity, AuthResult, parse_event,
)


class TestEventSchemas:

    def test_login_event_defaults(self):
        event = LoginEvent(
            source_ip="10.0.1.10",
            source_host="WS-001",
            username="alice",
            dest_host="SRV-DC1",
            dest_ip="10.0.2.10",
        )
        assert event.event_type == EventType.LOGIN
        assert event.severity == Severity.INFO
        assert event.auth_result == AuthResult.SUCCESS
        assert isinstance(event.event_id, str)
        assert isinstance(event.timestamp, datetime)

    def test_login_event_serialization(self):
        event = LoginEvent(
            source_ip="10.0.1.10",
            source_host="WS-001",
            username="bob",
            dest_host="SRV-FILE",
            dest_ip="10.0.2.11",
            severity=Severity.HIGH,
        )
        payload = event.to_kafka_payload()
        assert isinstance(payload, str)
        assert "bob" in payload
        assert "high" in payload

    def test_file_access_event_sensitive(self):
        event = FileAccessEvent(
            source_ip="10.0.1.10",
            source_host="WS-001",
            username="charlie",
            file_path="/etc/shadow",
            operation="read",
            is_sensitive=True,
            severity=Severity.CRITICAL,
        )
        assert event.is_sensitive is True
        assert event.severity == Severity.CRITICAL

    def test_network_conn_event_external(self):
        event = NetworkConnectionEvent(
            source_ip="10.0.1.10",
            source_host="WS-001",
            dest_ip="185.220.101.47",
            dest_port=4444,
            is_internal=False,
            severity=Severity.HIGH,
        )
        assert event.is_internal is False
        assert event.dest_port == 4444

    def test_parse_event_login(self):
        data = {
            "event_type": "login",
            "source_ip": "10.0.1.10",
            "source_host": "WS-001",
            "username": "dave",
            "dest_host": "SRV-DB",
            "dest_ip": "10.0.2.12",
            "severity": "medium",
        }
        event = parse_event(data)
        assert isinstance(event, LoginEvent)
        assert event.username == "dave"

    def test_process_event_unsigned(self):
        event = ProcessSpawnEvent(
            source_ip="10.0.1.10",
            source_host="WS-001",
            username="alice",
            process_name="mimikatz.exe",
            process_id=4567,
            parent_process="cmd.exe",
            command_line="mimikatz.exe --dump",
            is_signed=False,
            severity=Severity.CRITICAL,
        )
        assert event.is_signed is False
        assert event.severity == Severity.CRITICAL
