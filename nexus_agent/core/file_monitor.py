"""
NEXUS Endpoint Agent — File Monitor.

Continuously monitors configured directories for file system events:
  - Created / Modified / Deleted / Moved
  - Filters by monitored file extensions
  - Detects cross-volume copies (file_copied events)
  - Auto-encrypts new files when configured
  - Debounces rapid duplicate events

Uses the ``watchdog`` library for platform-native filesystem events.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from core.models import EventType, SecurityEvent, Severity
from utils.logging_config import get_logger
from utils.platform_info import get_hostname, get_local_ip, get_username

if TYPE_CHECKING:
    from config import NexusConfig
    from core.encryption_engine import EncryptionEngine
    from database.local_store import LocalStore
    from services.event_sender import EventSender

logger = get_logger(__name__)

# Debounce window: ignore duplicate events for the same file within this period
_DEBOUNCE_SECONDS = 2.0

# Encrypted file extension to ignore
_ENCRYPTED_EXT = ".ndlp"


class _NexusFileHandler(FileSystemEventHandler):
    """
    Watchdog event handler that generates NEXUS SecurityEvents.

    Filters by extension, debounces duplicates, and optionally
    triggers auto-encryption for new files.
    """

    def __init__(
        self,
        config: NexusConfig,
        event_sender: EventSender,
        encryption_engine: EncryptionEngine | None,
        local_store: LocalStore,
        auto_encrypt: bool = False,
        source_label: str = "local",
    ) -> None:
        super().__init__()
        self._config = config
        self._sender = event_sender
        self._engine = encryption_engine
        self._store = local_store
        self._auto_encrypt = auto_encrypt
        self._source_label = source_label
        self._device = config.device.resolved_name()
        self._last_events: dict[str, float] = {}
        self._lock = threading.Lock()

    # ---- Debounce -------------------------------------------------

    def _should_process(self, path: str, event_type: str) -> bool:
        """Return True if this event is not a debounce duplicate."""
        key = f"{event_type}:{path}"
        now = time.time()
        with self._lock:
            last = self._last_events.get(key, 0.0)
            if now - last < _DEBOUNCE_SECONDS:
                return False
            self._last_events[key] = now
            return True

    # ---- Extension filter -----------------------------------------

    def _is_monitored(self, path: str) -> bool:
        """Check if a file's extension is in the monitored set."""
        p = Path(path)
        if p.suffix == _ENCRYPTED_EXT:
            return False
        return self._config.monitoring.is_monitored_extension(p.suffix)

    # ---- Event helpers --------------------------------------------

    def _file_info(self, path: str) -> dict:
        """Gather file metadata for event fields."""
        p = Path(path)
        try:
            size = p.stat().st_size if p.exists() else 0
        except OSError:
            size = 0
        return {
            "file_name": p.name,
            "file_type": p.suffix.lower(),
            "file_path": str(p),
            "file_size": size,
        }

    def _send_event(
        self,
        event_type: EventType,
        severity: Severity,
        action: str,
        path: str,
        **extra: str,
    ) -> None:
        """Construct and send a SecurityEvent."""
        info = self._file_info(path)
        self._sender.send(SecurityEvent(
            event_type=event_type,
            severity=severity,
            action=action,
            device_name=self._device,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
            device_type=self._source_label,
            **info,
            **extra,
        ))

    # ---- Watchdog overrides ---------------------------------------

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if not self._is_monitored(event.src_path):
            return
        if not self._should_process(event.src_path, "created"):
            return

        logger.info("File created: %s", event.src_path)
        # Event ignored to reduce noise

        # Auto-encrypt if configured
        if self._auto_encrypt and self._engine:
            # Small delay to let the file finish writing
            time.sleep(0.5)
            try:
                result = self._engine.encrypt_file(event.src_path)
                if result:
                    logger.info("Auto-encrypted: %s", event.src_path)
            except Exception as exc:
                logger.error("Auto-encryption failed for %s: %s", event.src_path, exc)
                self._send_event(
                    EventType.FILE_ENCRYPTED,
                    Severity.HIGH,
                    f"Auto-encryption failed: {Path(event.src_path).name} — {exc}",
                    event.src_path,
                    status="failed",
                )

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if not self._is_monitored(event.src_path):
            return
        if not self._should_process(event.src_path, "modified"):
            return

        # Skip if file is currently protected (encrypted)
        if self._store.is_file_protected(str(Path(event.src_path).resolve())):
            return

        logger.debug("File modified: %s", event.src_path)
        # Event ignored to reduce noise

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if not self._is_monitored(event.src_path):
            return
        if not self._should_process(event.src_path, "deleted"):
            return

        logger.info("File deleted: %s", event.src_path)
        # Event ignored to reduce noise

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        src = getattr(event, "src_path", "")
        dest = getattr(event, "dest_path", "")

        if not (self._is_monitored(src) or self._is_monitored(dest)):
            return
        if not self._should_process(src, "moved"):
            return

        # Detect cross-volume copy vs. rename
        src_vol = self._get_volume(src)
        dest_vol = self._get_volume(dest)

        if src_vol != dest_vol:
            # Cross-volume → treat as FILE_COPIED
            logger.info("File copied cross-volume: %s → %s", src, dest)
            self._send_event(
                EventType.FILE_COPIED,
                Severity.MEDIUM,
                f"File copied: {Path(src).name} → {dest}",
                src,
                remarks=f"source={src} destination={dest} src_volume={src_vol} dest_volume={dest_vol}",
            )
        else:
            # Same volume → rename / move
            logger.info("File moved: %s → %s", src, dest)
            # Event ignored to reduce noise

    # ---- Helpers --------------------------------------------------

    @staticmethod
    def _get_volume(path: str) -> str:
        """Return the mount point / volume for a given path (macOS)."""
        try:
            return os.path.splitdrive(path)[0] or str(Path(path).resolve().parts[1] if len(Path(path).resolve().parts) > 1 else "/")
        except Exception:
            return "/"


class FileMonitor:
    """
    Orchestrates watchdog observers across multiple monitored paths.

    Manages the lifecycle of observers: start, stop, and dynamic
    addition of new paths (e.g., when a USB is inserted).
    """

    def __init__(
        self,
        config: NexusConfig,
        encryption_engine: EncryptionEngine | None,
        event_sender: EventSender,
        local_store: LocalStore,
    ) -> None:
        self._config = config
        self._engine = encryption_engine
        self._sender = event_sender
        self._store = local_store
        self._observers: dict[str, Observer] = {}
        self._lock = threading.Lock()
        logger.info("FileMonitor initialized")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start monitoring all configured watch paths."""
        paths = self._config.monitoring.resolved_watch_paths()
        for path in paths:
            self.add_watch_path(path, auto_encrypt=self._config.monitoring.auto_encrypt_on_local)
        logger.info("FileMonitor started (%d paths)", len(self._observers))

    def stop(self) -> None:
        """Stop all observers."""
        with self._lock:
            for path_str, observer in list(self._observers.items()):
                try:
                    observer.stop()
                    observer.join(timeout=5)
                    logger.debug("Stopped observer for %s", path_str)
                except Exception as exc:
                    logger.error("Error stopping observer for %s: %s", path_str, exc)
            self._observers.clear()
        logger.info("FileMonitor stopped")

    # ------------------------------------------------------------------
    # Dynamic path management
    # ------------------------------------------------------------------

    def add_watch_path(
        self,
        path: Path | str,
        auto_encrypt: bool = False,
        source_label: str = "local",
    ) -> bool:
        """
        Add a new directory to the monitoring set.

        Parameters
        ----------
        path : Path or str
            Directory to monitor.
        auto_encrypt : bool
            Whether to auto-encrypt new files in this path.
        source_label : str
            Label for the source type (e.g., 'local', 'usb', 'external').

        Returns True if the path was added successfully.
        """
        path = Path(path).resolve()
        path_str = str(path)

        if not path.exists():
            logger.warning("Watch path does not exist, creating: %s", path)
            path.mkdir(parents=True, exist_ok=True)

        with self._lock:
            if path_str in self._observers:
                logger.debug("Already monitoring: %s", path_str)
                return False

            handler = _NexusFileHandler(
                config=self._config,
                event_sender=self._sender,
                encryption_engine=self._engine,
                local_store=self._store,
                auto_encrypt=auto_encrypt,
                source_label=source_label,
            )

            observer = Observer()
            observer.schedule(
                handler,
                str(path),
                recursive=self._config.monitoring.recursive,
            )
            observer.daemon = True
            observer.start()
            self._observers[path_str] = observer
            logger.info("Now monitoring: %s (auto_encrypt=%s, label=%s)",
                        path_str, auto_encrypt, source_label)
            return True

    def remove_watch_path(self, path: Path | str) -> bool:
        """
        Remove a directory from the monitoring set.

        Returns True if the path was being monitored and was removed.
        """
        path_str = str(Path(path).resolve())
        with self._lock:
            observer = self._observers.pop(path_str, None)
            if observer:
                observer.stop()
                observer.join(timeout=5)
                logger.info("Stopped monitoring: %s", path_str)
                return True
            return False

    @property
    def watched_paths(self) -> list[str]:
        """Return list of currently monitored paths."""
        with self._lock:
            return list(self._observers.keys())
