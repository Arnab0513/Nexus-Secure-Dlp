"""
NEXUS Endpoint Agent — Data Models.

Defines the canonical data structures used across every module:
SecurityEvent, EventType, Severity, FileRecord, DeviceInfo.
"""

from __future__ import annotations

import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ------------------------------------------------------------------
# Enumerations
# ------------------------------------------------------------------

class EventType(str, Enum):
    """All recognized event types in the NEXUS system."""

    FILE_OPENED = "file_opened"
    FILE_CLOSED = "file_closed"
    FILE_ENCRYPTED = "file_encrypted"
    FILE_DECRYPTED = "file_decrypted"
    FILE_COPIED = "file_copied"
    FILE_MOVED = "file_moved"
    FILE_DELETED = "file_deleted"
    USB_INSERTED = "usb_inserted"
    USB_REMOVED = "usb_removed"
    WRONG_PASSWORD = "wrong_password"
    UNAUTHORIZED_DEVICE = "unauthorized_device"
    INTRUDER_IMAGE_CAPTURED = "intruder_image_captured"
    HEARTBEAT = "heartbeat"
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"


class Severity(str, Enum):
    """Three-tier severity classification."""

    NORMAL = "NORMAL"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FileRecordStatus(str, Enum):
    """Lifecycle status of a protected file."""

    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"
    PENDING = "pending"
    DELETED = "deleted"


class DeviceStatus(str, Enum):
    """Status of a connected storage device."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    BLOCKED = "blocked"


# ------------------------------------------------------------------
# SecurityEvent
# ------------------------------------------------------------------

def _generate_event_id() -> str:
    """Generate a unique event identifier."""
    return uuid.uuid4().hex[:16]


def _now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class SecurityEvent:
    """
    Canonical security event reported to the SOC server.

    Every event contains all 18 fields specified in the NEXUS protocol.
    Fields with sensible defaults are auto-populated.
    """

    event_type: EventType
    severity: Severity
    action: str

    # Identity — auto-populated if not supplied
    event_id: str = field(default_factory=_generate_event_id)
    timestamp: str = field(default_factory=_now_iso)
    computer_name: str = field(default_factory=socket.gethostname)
    username: str = ""
    ip_address: str = ""

    # Device context
    device_name: str = ""
    device_type: str = ""

    # File context
    file_name: str = "-"
    file_type: str = ""
    file_path: str = ""
    file_size: int = 0

    # Status
    status: str = "ok"
    attempt_count: int = 0
    captured_image_path: str = ""
    remarks: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a flat dictionary for JSON transport."""
        data = asdict(self)
        # Ensure enum values are strings
        data["event_type"] = str(self.event_type.value)
        data["severity"] = str(self.severity.value)
        return data

    def to_server_payload(self) -> dict[str, Any]:
        """
        Build the payload matching the server's ``/client/log-event`` API.

        The server expects: device, file, action, severity.
        We include the full event in a nested ``event_data`` key for
        richer logging while remaining backward-compatible.
        """
        payload = {
            "device": self.device_name or self.computer_name,
            "file": self.file_name,
            "action": self.action,
            "severity": str(self.severity.value),
            "event_data": self.to_dict(),
        }
        
        if self.captured_image_path:
            from core.intruder_capture import IntruderCapture
            b64_img = IntruderCapture.encode_image_b64(self.captured_image_path)
            if b64_img:
                payload["intrusion_image_b64"] = b64_img
                
        return payload


# ------------------------------------------------------------------
# FileRecord
# ------------------------------------------------------------------

@dataclass
class FileRecord:
    """
    Tracks a protected file through its encryption lifecycle.

    Stored in the local SQLite database.
    """

    file_path: str
    original_hash: str = ""
    encrypted_path: str = ""
    file_key_encrypted: str = ""
    auth_token: str = ""
    status: FileRecordStatus = FileRecordStatus.PENDING
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    file_name: str = ""
    file_type: str = ""
    file_size: int = 0

    def __post_init__(self) -> None:
        if not self.file_name and self.file_path:
            from pathlib import Path
            p = Path(self.file_path)
            self.file_name = p.name
            self.file_type = p.suffix.lower()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        data = asdict(self)
        data["status"] = str(self.status.value)
        return data


# ------------------------------------------------------------------
# DeviceInfo
# ------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """
    Represents a connected storage device (USB, external HDD/SSD, etc.).
    """

    device_name: str
    device_id: str = ""
    device_type: str = "removable"  # removable | external_hdd | external_ssd | unknown
    mount_point: str = ""
    drive_letter: str = ""  # Windows-style; on macOS this is the volume name
    filesystem_type: str = ""
    total_size_bytes: int = 0
    status: DeviceStatus = DeviceStatus.CONNECTED
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        data = asdict(self)
        data["status"] = str(self.status.value)
        return data
