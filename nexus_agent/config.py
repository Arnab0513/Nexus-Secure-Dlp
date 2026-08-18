"""
NEXUS Endpoint Agent — Centralized Configuration.

Loads settings from config.yaml with environment variable overrides.
Every module imports this single source of truth.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


_BASE_DIR = Path(__file__).resolve().parent
_DEFAULT_CONFIG_PATH = _BASE_DIR / "config.yaml"


# ------------------------------------------------------------------
# Nested configuration sections
# ------------------------------------------------------------------

@dataclass(frozen=True)
class ServerConfig:
    """Flask SOC server connection settings."""
    url: str = "http://127.0.0.1:5050"
    timeout_seconds: int = 20


@dataclass(frozen=True)
class DeviceConfig:
    """Identity of this endpoint."""
    name: str = ""

    def resolved_name(self) -> str:
        """Return the device name, falling back to hostname."""
        return self.name or socket.gethostname()


@dataclass(frozen=True)
class AdminConfig:
    """Administrator notification settings."""
    email: str = ""


@dataclass(frozen=True)
class EncryptionConfig:
    """Encryption algorithm settings."""
    algorithm: str = "AES-256-Fernet"


@dataclass(frozen=True)
class MonitoringConfig:
    """File and directory monitoring settings."""
    watch_paths: list[str] = field(default_factory=lambda: [
        "~/Desktop", "~/Documents", "~/Downloads",
    ])
    file_extensions: list[str] = field(default_factory=lambda: [
        ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv",
        ".jpg", ".jpeg", ".png", ".zip", ".rar",
    ])
    recursive: bool = True
    poll_interval_seconds: int = 1
    auto_encrypt_on_usb: bool = True
    auto_encrypt_on_local: bool = False

    def resolved_watch_paths(self) -> list[Path]:
        """Expand ~ and return absolute Path objects."""
        return [Path(p).expanduser().resolve() for p in self.watch_paths]

    def is_monitored_extension(self, ext: str) -> bool:
        """Check whether a file extension is in the monitored set."""
        return ext.lower() in {e.lower() for e in self.file_extensions}


@dataclass(frozen=True)
class HeartbeatConfig:
    """Heartbeat interval to the SOC server."""
    interval_seconds: int = 60


@dataclass(frozen=True)
class EventQueueConfig:
    """Offline event queue / retry settings."""
    max_retries: int = 5
    retry_delay_seconds: int = 10
    batch_size: int = 25


@dataclass(frozen=True)
class IntruderCaptureConfig:
    """Webcam intruder capture settings."""
    enabled: bool = True
    camera: str = "builtin"
    max_attempts_before_block: int = 3


@dataclass(frozen=True)
class LoggingConfig:
    """Structured logging settings."""
    level: str = "INFO"
    file: str = "logs/nexus_agent.log"
    max_bytes: int = 10_485_760  # 10 MB
    backup_count: int = 5

    def resolved_file(self) -> Path:
        """Return absolute path, relative to agent base directory."""
        p = Path(self.file)
        if not p.is_absolute():
            p = _BASE_DIR / p
        return p


# ------------------------------------------------------------------
# Top-level configuration
# ------------------------------------------------------------------

@dataclass(frozen=True)
class NexusConfig:
    """Root configuration object for the NEXUS Endpoint Agent."""

    server: ServerConfig = field(default_factory=ServerConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)
    admin: AdminConfig = field(default_factory=AdminConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    event_queue: EventQueueConfig = field(default_factory=EventQueueConfig)
    intruder_capture: IntruderCaptureConfig = field(default_factory=IntruderCaptureConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # ---- factory ---------------------------------------------------

    @classmethod
    def load(cls, path: Path | str | None = None) -> NexusConfig:
        """Load configuration from YAML file with environment overrides.

        Parameters
        ----------
        path : Path or str, optional
            Path to config.yaml.  Defaults to ``<agent_dir>/config.yaml``.
        """
        config_path = Path(path) if path else _DEFAULT_CONFIG_PATH
        raw: dict[str, Any] = {}
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}

        # Apply environment variable overrides
        raw = cls._apply_env_overrides(raw)

        return cls(
            server=cls._build_section(ServerConfig, raw.get("server")),
            device=cls._build_section(DeviceConfig, raw.get("device")),
            admin=cls._build_section(AdminConfig, raw.get("admin")),
            encryption=cls._build_section(EncryptionConfig, raw.get("encryption")),
            monitoring=cls._build_section(MonitoringConfig, raw.get("monitoring")),
            heartbeat=cls._build_section(HeartbeatConfig, raw.get("heartbeat")),
            event_queue=cls._build_section(EventQueueConfig, raw.get("event_queue")),
            intruder_capture=cls._build_section(IntruderCaptureConfig, raw.get("intruder_capture")),
            logging=cls._build_section(LoggingConfig, raw.get("logging")),
        )

    # ---- validation ------------------------------------------------

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []
        if not self.server.url.startswith(("http://", "https://")):
            errors.append(f"server.url must start with http:// or https://, got '{self.server.url}'")
        if not (1 <= self.server.timeout_seconds <= 300):
            errors.append(f"server.timeout_seconds must be 1..300, got {self.server.timeout_seconds}")
        for ext in self.monitoring.file_extensions:
            if not ext.startswith("."):
                errors.append(f"File extension must start with '.', got '{ext}'")
        if self.heartbeat.interval_seconds < 10:
            errors.append(f"heartbeat.interval_seconds must be >= 10, got {self.heartbeat.interval_seconds}")
        return errors

    # ---- helpers ---------------------------------------------------

    @staticmethod
    def _build_section(cls: type, raw_section: dict | None):
        """Construct a dataclass from a raw dict, ignoring unknown keys."""
        if not raw_section or not isinstance(raw_section, dict):
            return cls()
        # Filter to only known field names
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in raw_section.items() if k in known_fields}
        return cls(**filtered)

    @staticmethod
    def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
        """Override config values with NEXUS_ prefixed environment variables."""
        env_map = {
            "NEXUS_SERVER_URL": ("server", "url"),
            "NEXUS_SERVER_TIMEOUT": ("server", "timeout_seconds"),
            "NEXUS_DEVICE_NAME": ("device", "name"),
            "NEXUS_ADMIN_EMAIL": ("admin", "email"),
            "NEXUS_LOG_LEVEL": ("logging", "level"),
            "NEXUS_HEARTBEAT_INTERVAL": ("heartbeat", "interval_seconds"),
        }
        for env_key, (section, field_name) in env_map.items():
            value = os.environ.get(env_key)
            if value is not None:
                raw.setdefault(section, {})
                # Attempt int conversion for numeric fields
                try:
                    value = int(value)  # type: ignore[assignment]
                except ValueError:
                    pass
                raw[section][field_name] = value
        return raw

    # ---- repr ------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"NexusConfig(\n"
            f"  server={self.server!r},\n"
            f"  device_name='{self.device.resolved_name()}',\n"
            f"  monitoring.watch_paths={self.monitoring.watch_paths},\n"
            f"  monitoring.extensions={self.monitoring.file_extensions},\n"
            f"  heartbeat={self.heartbeat.interval_seconds}s,\n"
            f"  intruder_capture.enabled={self.intruder_capture.enabled}\n"
            f")"
        )


# ------------------------------------------------------------------
# Convenience: base directory accessor
# ------------------------------------------------------------------

def agent_base_dir() -> Path:
    """Return the root directory of the nexus_agent package."""
    return _BASE_DIR
