"""
NEXUS Endpoint Agent — Device Monitor.

Detects USB drives, external HDD/SSD, pen drives, and other removable
media on macOS by polling ``/Volumes/``.

On device insertion:
  1. Log device to local DB.
  2. Emit USB_INSERTED event.
  3. Scan for monitored file types.
  4. Start file monitoring on the new mount point.

On device removal:
  1. Emit USB_REMOVED event.
  2. Stop file monitoring for that mount point.
  3. Update device status in local DB.

Architecture:
  BaseDeviceMonitor (abstract) → MacOSDeviceMonitor (concrete)
  Extensible for Windows/Linux via subclasses.
"""

from __future__ import annotations

import abc
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from core.models import DeviceInfo, DeviceStatus, EventType, SecurityEvent, Severity
from utils.logging_config import get_logger
from utils.platform_info import get_hostname, get_local_ip, get_username

if TYPE_CHECKING:
    from config import NexusConfig
    from core.file_monitor import FileMonitor
    from database.local_store import LocalStore
    from services.event_sender import EventSender

logger = get_logger(__name__)

# Volumes that are always present and should be ignored
_MACOS_SYSTEM_VOLUMES = frozenset({
    "Macintosh HD",
    "Macintosh HD - Data",
    "Recovery",
    "Preboot",
    "VM",
    "Update",
    "com.apple.TimeMachine.localsnapshots",
})


class BaseDeviceMonitor(abc.ABC):
    """Abstract base for platform-specific device monitors."""

    @abc.abstractmethod
    def start(self) -> None: ...

    @abc.abstractmethod
    def stop(self) -> None: ...


class MacOSDeviceMonitor(BaseDeviceMonitor):
    """
    macOS device monitor — polls ``/Volumes/`` for mount changes.

    Detects new and removed external volumes by comparing snapshots
    of the ``/Volumes/`` directory at a configurable interval.
    """

    def __init__(
        self,
        config: NexusConfig,
        event_sender: EventSender,
        local_store: LocalStore,
        file_monitor: FileMonitor | None = None,
    ) -> None:
        self._config = config
        self._sender = event_sender
        self._store = local_store
        self._file_monitor = file_monitor
        self._device_name = config.device.resolved_name()
        self._poll_interval = config.monitoring.poll_interval_seconds
        self._auto_encrypt_usb = config.monitoring.auto_encrypt_on_usb
        self._running = False
        self._stop_event = threading.Event()
        self._poll_thread: threading.Thread | None = None
        self._known_volumes: set[str] = set()
        logger.info("MacOSDeviceMonitor initialized (poll_interval=%ds)", self._poll_interval)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start polling for device changes."""
        if self._running:
            return

        # Take initial snapshot
        self._known_volumes = self._get_external_volumes()
        logger.info("Initial volumes: %s", self._known_volumes or "(none)")

        self._running = True
        self._stop_event.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="nexus-device-monitor",
            daemon=True,
        )
        self._poll_thread.start()
        logger.info("MacOSDeviceMonitor started")

    def stop(self) -> None:
        """Stop polling."""
        self._running = False
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=10)
        logger.info("MacOSDeviceMonitor stopped")

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Background thread: compare volume snapshots at each interval."""
        while not self._stop_event.is_set():
            try:
                current = self._get_external_volumes()
                inserted = current - self._known_volumes
                removed = self._known_volumes - current

                for vol in inserted:
                    self._on_device_inserted(vol)

                for vol in removed:
                    self._on_device_removed(vol)

                self._known_volumes = current

            except Exception as exc:
                logger.error("Device monitor poll error: %s", exc)

            self._stop_event.wait(timeout=self._poll_interval)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_device_inserted(self, volume_name: str) -> None:
        """Handle a newly inserted device."""
        mount_point = f"/Volumes/{volume_name}"
        logger.info("Device inserted: %s at %s", volume_name, mount_point)

        device_info = self._build_device_info(volume_name, mount_point)

        # Store in local DB
        self._store.add_device(
            device_name=volume_name,
            device_id=device_info.device_id,
            device_type=device_info.device_type,
            mount_point=mount_point,
            drive_letter=volume_name,
            filesystem_type=device_info.filesystem_type,
            total_size_bytes=device_info.total_size_bytes,
        )

        # Emit event
        self._sender.send(SecurityEvent(
            event_type=EventType.USB_INSERTED,
            severity=Severity.MEDIUM,
            action=f"Storage device inserted: {volume_name} ({device_info.device_type})",
            device_name=self._device_name,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
            device_type=device_info.device_type,
            file_name=volume_name,
            file_path=mount_point,
            file_size=device_info.total_size_bytes,
            remarks=f"fs={device_info.filesystem_type}",
        ))

        # Scan for monitored files
        monitored_count = self._scan_for_monitored_files(mount_point)
        if monitored_count > 0:
            logger.info("Found %d monitored files on %s", monitored_count, volume_name)

        # Start file monitoring on the new volume
        if self._file_monitor:
            self._file_monitor.add_watch_path(
                mount_point,
                auto_encrypt=self._auto_encrypt_usb,
                source_label=device_info.device_type,
            )

    def _on_device_removed(self, volume_name: str) -> None:
        """Handle a removed device."""
        mount_point = f"/Volumes/{volume_name}"
        logger.info("Device removed: %s", volume_name)

        # Update DB
        self._store.update_device_status(mount_point, DeviceStatus.DISCONNECTED.value)

        # Stop file monitoring
        if self._file_monitor:
            self._file_monitor.remove_watch_path(mount_point)

        # Emit event
        self._sender.send(SecurityEvent(
            event_type=EventType.USB_REMOVED,
            severity=Severity.MEDIUM,
            action=f"Storage device removed: {volume_name}",
            device_name=self._device_name,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
            file_name=volume_name,
            file_path=mount_point,
        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_external_volumes() -> set[str]:
        """Return the set of currently mounted external volumes."""
        volumes_dir = Path("/Volumes")
        if not volumes_dir.exists():
            return set()

        current: set[str] = set()
        try:
            for entry in volumes_dir.iterdir():
                if entry.name in _MACOS_SYSTEM_VOLUMES:
                    continue
                if entry.is_dir() or entry.is_symlink():
                    current.add(entry.name)
        except PermissionError:
            pass
        return current

    def _build_device_info(self, volume_name: str, mount_point: str) -> DeviceInfo:
        """
        Gather device metadata using macOS ``diskutil``.

        Falls back to shutil.disk_usage if diskutil is unavailable.
        """
        device_type = "removable"
        fs_type = ""
        total_bytes = 0
        device_id = ""

        try:
            # Try diskutil info
            result = subprocess.run(
                ["diskutil", "info", mount_point],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Device Identifier:"):
                        device_id = line.split(":", 1)[1].strip()
                    elif line.startswith("File System Personality:"):
                        fs_type = line.split(":", 1)[1].strip()
                    elif line.startswith("Disk Size:"):
                        # Parse "Disk Size: 31.0 GB (31029329920 Bytes)"
                        try:
                            bytes_str = line.split("(")[1].split(" ")[0]
                            total_bytes = int(bytes_str)
                        except (IndexError, ValueError):
                            pass
                    elif "Removable Media:" in line:
                        is_removable = "Removable" in line.split(":", 1)[1]
                        if not is_removable:
                            device_type = "external_hdd"
                    elif "Solid State:" in line:
                        is_ssd = "Yes" in line.split(":", 1)[1]
                        if is_ssd and device_type == "external_hdd":
                            device_type = "external_ssd"
        except Exception as exc:
            logger.debug("diskutil failed for %s: %s", mount_point, exc)

        # Fallback for total size
        if total_bytes == 0:
            try:
                usage = shutil.disk_usage(mount_point)
                total_bytes = usage.total
            except Exception:
                pass

        return DeviceInfo(
            device_name=volume_name,
            device_id=device_id,
            device_type=device_type,
            mount_point=mount_point,
            drive_letter=volume_name,
            filesystem_type=fs_type,
            total_size_bytes=total_bytes,
        )

    def _scan_for_monitored_files(self, mount_point: str) -> int:
        """Count monitored file types present on a newly inserted device."""
        count = 0
        try:
            mount_path = Path(mount_point)
            for ext in self._config.monitoring.file_extensions:
                count += len(list(mount_path.rglob(f"*{ext}")))
        except (PermissionError, OSError) as exc:
            logger.debug("Scan error on %s: %s", mount_point, exc)
        return count


# ------------------------------------------------------------------
# Factory function
# ------------------------------------------------------------------

def create_device_monitor(
    config: NexusConfig,
    event_sender: EventSender,
    local_store: LocalStore,
    file_monitor: FileMonitor | None = None,
) -> BaseDeviceMonitor:
    """
    Create the appropriate device monitor for the current platform.

    Currently only macOS is implemented.
    """
    import platform
    if platform.system() == "Darwin":
        return MacOSDeviceMonitor(config, event_sender, local_store, file_monitor)
    else:
        logger.warning("No device monitor available for %s — using macOS fallback", platform.system())
        return MacOSDeviceMonitor(config, event_sender, local_store, file_monitor)
