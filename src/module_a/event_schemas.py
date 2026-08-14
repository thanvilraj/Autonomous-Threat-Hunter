# ============================================================
#  Module A — Event Schemas
#  Pydantic models for all network event types ingested
#  via Kafka. Provides strict validation and serialization.
# ============================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any

from pydantic import BaseModel, Field


# ── Enumerations ─────────────────────────────────────────────

class EventType(str, Enum):
    LOGIN          = "login"
    LOGOUT         = "logout"
    FILE_ACCESS    = "file_access"
    FILE_MODIFY    = "file_modify"
    PROCESS_SPAWN  = "process_spawn"
    NETWORK_CONN   = "network_connection"
    PRIVILEGE_ESC  = "privilege_escalation"
    LATERAL_MOVE   = "lateral_movement"
    DATA_EXFIL     = "data_exfiltration"


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class AuthResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKOUT = "lockout"


# ── Base Event ───────────────────────────────────────────────

class BaseEvent(BaseModel):
    """Common fields shared by all event types."""
    event_id:   str       = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    timestamp:  datetime  = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip:  str
    source_host: str
    severity:   Severity  = Severity.INFO
    raw_log:    Optional[str] = None
    metadata:   dict[str, Any] = Field(default_factory=dict)

    def to_kafka_payload(self) -> str:
        return self.model_dump_json()


# ── Concrete Event Types ─────────────────────────────────────

class LoginEvent(BaseEvent):
    """
    User authentication event (SSH, RDP, Kerberos, local).
    """
    event_type: EventType = EventType.LOGIN
    username:       str
    dest_host:      str
    dest_ip:        str
    auth_method:    str   = "password"   # password | kerberos | ssh_key | ntlm
    auth_result:    AuthResult = AuthResult.SUCCESS
    failed_attempts: int  = 0


class FileAccessEvent(BaseEvent):
    """
    File read / write / delete operation on a host.
    """
    event_type: EventType = EventType.FILE_ACCESS
    username:   str
    file_path:  str
    operation:  str       # read | write | delete | rename
    file_size_bytes: Optional[int] = None
    is_sensitive: bool    = False   # True for /etc/passwd, SAM hive, etc.


class ProcessSpawnEvent(BaseEvent):
    """
    New process started on a host — key indicator of C2 / malware.
    """
    event_type:   EventType = EventType.PROCESS_SPAWN
    username:     str
    process_name: str
    process_id:   int
    parent_process: str
    command_line:   str
    is_signed:      bool = True   # Unsigned binaries are suspicious


class NetworkConnectionEvent(BaseEvent):
    """
    TCP/UDP connection between two hosts.
    """
    event_type:  EventType = EventType.NETWORK_CONN
    dest_ip:     str
    dest_host:   Optional[str] = None
    dest_port:   int
    protocol:    str   = "TCP"
    bytes_sent:  int   = 0
    bytes_recv:  int   = 0
    is_internal: bool  = True    # Internal LAN vs external internet
    is_encrypted: bool = False


class PrivilegeEscalationEvent(BaseEvent):
    """
    A user gained elevated privileges (sudo, UAC bypass, token impersonation).
    """
    event_type:    EventType = EventType.PRIVILEGE_ESC
    username:      str
    original_role: str
    elevated_role: str
    method:        str  # sudo | runas | token_impersonation | exploit


# ── Union type for deserialization ───────────────────────────

EVENT_REGISTRY: dict[EventType, type[BaseEvent]] = {
    EventType.LOGIN:        LoginEvent,
    EventType.FILE_ACCESS:  FileAccessEvent,
    EventType.FILE_MODIFY:  FileAccessEvent,
    EventType.PROCESS_SPAWN: ProcessSpawnEvent,
    EventType.NETWORK_CONN: NetworkConnectionEvent,
    EventType.PRIVILEGE_ESC: PrivilegeEscalationEvent,
}


def parse_event(data: dict) -> BaseEvent:
    """Deserialize a raw dict into the correct typed event model."""
    event_type = EventType(data.get("event_type", "login"))
    model_class = EVENT_REGISTRY.get(event_type, BaseEvent)
    return model_class(**data)
