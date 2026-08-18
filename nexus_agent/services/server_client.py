"""
NEXUS Endpoint Agent — Server Client.

Typed HTTP wrapper around all ``/client/*`` REST endpoints on the Flask
SOC server.  Every method handles timeouts, connection errors, and HTTP
status codes, returning structured results or raising clear exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from config import NexusConfig
from utils.logging_config import get_logger
from utils.platform_info import get_hostname

logger = get_logger(__name__)


# ------------------------------------------------------------------
# Response types
# ------------------------------------------------------------------

@dataclass
class EnrollResponse:
    """Result of ``/client/enroll``."""
    status: str
    server_time: str
    session_id: str = ""


@dataclass
class EncryptionResponse:
    """Result of ``/client/request-encryption``."""
    file_key: str
    department: str
    key_version: int
    block: dict[str, Any]


@dataclass
class DecryptionResponse:
    """Result of ``/client/request-decryption``."""
    status: str
    file_key: str
    block: dict[str, Any]


# ------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------

class ServerError(Exception):
    """Raised when the server returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ServerUnavailable(Exception):
    """Raised when the server cannot be reached."""


# ------------------------------------------------------------------
# Server Client
# ------------------------------------------------------------------

class ServerClient:
    """
    Typed HTTP client for the NEXUS SOC server.

    Each public method maps to exactly one server endpoint.
    All methods are synchronous and raise on failure.
    """

    def __init__(self, config: NexusConfig) -> None:
        self._base_url = config.server.url.rstrip("/")
        self._timeout = config.server.timeout_seconds
        self._device_name = config.device.resolved_name()
        self._session_id: str = ""
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-NEXUS-Device": self._device_name,
        })

    # ---- Endpoint wrappers ----------------------------------------

    def enroll(self) -> EnrollResponse:
        """Register this device with the SOC server."""
        data = self._post("/client/enroll", {"device": self._device_name})
        self._session_id = data.get("session_id", "")
        return EnrollResponse(
            status=data.get("status", ""),
            server_time=data.get("server_time", ""),
            session_id=self._session_id,
        )

    def request_encryption(self, file_name: str, department: str | None = None) -> EncryptionResponse:
        """Request a new encryption key for a file."""
        payload = {
            "device": self._device_name,
            "file_name": file_name,
        }
        if department:
            payload["department"] = department
            
        data = self._post("/client/request-encryption", payload)
        return EncryptionResponse(
            file_key=data["file_key"],
            department=data.get("department", "DA"),
            key_version=data.get("key_version", 1),
            block=data.get("block", {}),
        )

    def request_decryption(
        self,
        auth_token: str,
        file_name: str,
        intrusion_image_b64: str | None = None,
        face_label: str = "not-captured",
    ) -> DecryptionResponse:
        """Request decryption approval from the server."""
        payload: dict[str, Any] = {
            "device": self._device_name,
            "auth_token": auth_token,
            "file_name": file_name,
            "face_label": face_label,
        }
        if intrusion_image_b64:
            payload["intrusion_image_b64"] = intrusion_image_b64
        data = self._post("/client/request-decryption", payload)
        return DecryptionResponse(
            status=data.get("status", ""),
            file_key=data.get("file_key", ""),
            block=data.get("block", {}),
        )

    def log_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a single security event to the server."""
        # Attach session_id to heartbeat events for server validation
        action = payload.get("action", "")
        if "heartbeat" in action.lower() and self._session_id:
            payload["session_id"] = self._session_id
        return self._post("/client/log-event", payload)

    def deregister(self) -> None:
        """Deregister this agent's session with the server on shutdown."""
        if not self._session_id:
            return
        try:
            self._post("/client/deregister", {
                "device": self._device_name,
                "session_id": self._session_id,
            })
            logger.info("Session deregistered with server")
        except Exception as exc:
            logger.warning("Failed to deregister session: %s", exc)
        finally:
            self._session_id = ""

    def log_event_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Send multiple queued events in a single request."""
        return self._post("/client/log-event-batch", {"events": events})

    def is_available(self) -> bool:
        """Check whether the server is reachable (non-blocking)."""
        try:
            resp = self._session.get(
                f"{self._base_url}/login",
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ---- Internal -------------------------------------------------

    def _post(self, route: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        POST JSON to a server endpoint and return the parsed response.

        Raises
        ------
        ServerUnavailable
            If the server cannot be reached.
        ServerError
            If the server returns an HTTP error (4xx / 5xx).
        """
        url = f"{self._base_url}{route}"
        try:
            resp = self._session.post(url, json=payload, timeout=self._timeout)
        except requests.ConnectionError as exc:
            logger.error("Server unreachable at %s: %s", url, exc)
            raise ServerUnavailable(f"Cannot connect to {url}") from exc
        except requests.Timeout as exc:
            logger.error("Request to %s timed out", url)
            raise ServerUnavailable(f"Timeout connecting to {url}") from exc

        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json().get("error", resp.text)
            except Exception:
                detail = resp.text
            logger.warning("Server error %d on %s: %s", resp.status_code, route, detail)
            raise ServerError(resp.status_code, detail)

        return resp.json()
