"""
NEXUS Endpoint Agent — Local SQLite Store.

Thread-safe persistent storage for:
- Protected file registry
- Device information log
- Event queue (offline resilience)
- Key-value configuration store
- Encrypted key blobs
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from config import agent_base_dir
from utils.logging_config import get_logger

logger = get_logger(__name__)

_DEFAULT_DB_PATH = agent_base_dir() / "data" / "nexus_local.db"


class LocalStore:
    """
    SQLite-backed local state manager.

    All public methods are thread-safe via an internal ``threading.Lock``.
    The database file is created automatically on first use.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()
        logger.info("LocalStore initialized at %s", self._db_path)

    # ------------------------------------------------------------------
    # Schema initialization
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS protected_files (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path       TEXT NOT NULL UNIQUE,
                    original_hash   TEXT DEFAULT '',
                    encrypted_path  TEXT DEFAULT '',
                    file_key_encrypted TEXT DEFAULT '',
                    auth_token      TEXT DEFAULT '',
                    status          TEXT DEFAULT 'pending',
                    file_name       TEXT DEFAULT '',
                    file_type       TEXT DEFAULT '',
                    file_size       INTEGER DEFAULT 0,
                    created_at      TEXT DEFAULT (datetime('now')),
                    updated_at      TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name     TEXT NOT NULL,
                    device_id       TEXT DEFAULT '',
                    device_type     TEXT DEFAULT 'removable',
                    mount_point     TEXT DEFAULT '',
                    drive_letter    TEXT DEFAULT '',
                    filesystem_type TEXT DEFAULT '',
                    total_size_bytes INTEGER DEFAULT 0,
                    status          TEXT DEFAULT 'connected',
                    first_seen      TEXT DEFAULT (datetime('now')),
                    last_seen       TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS event_queue (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json      TEXT NOT NULL,
                    retry_count     INTEGER DEFAULT 0,
                    status          TEXT DEFAULT 'pending',
                    created_at      TEXT DEFAULT (datetime('now')),
                    last_attempt    TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS config_kv (
                    key             TEXT PRIMARY KEY,
                    value           TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS key_store (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name       TEXT NOT NULL UNIQUE,
                    encrypted_key_blob TEXT NOT NULL,
                    auth_token      TEXT DEFAULT '',
                    created_at      TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_pf_path
                    ON protected_files(file_path);
                CREATE INDEX IF NOT EXISTS idx_eq_status
                    ON event_queue(status);
                CREATE INDEX IF NOT EXISTS idx_ks_file
                    ON key_store(file_name);
                CREATE INDEX IF NOT EXISTS idx_dev_mount
                    ON devices(mount_point);
            """)
        logger.debug("Database schema initialized")

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a new SQLite connection with row factory enabled."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ------------------------------------------------------------------
    # Protected Files
    # ------------------------------------------------------------------

    def add_protected_file(
        self,
        file_path: str,
        original_hash: str,
        encrypted_path: str,
        file_key_encrypted: str,
        auth_token: str,
        file_name: str = "",
        file_type: str = "",
        file_size: int = 0,
    ) -> int:
        """Insert or update a protected file record. Returns row id."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO protected_files
                        (file_path, original_hash, encrypted_path,
                         file_key_encrypted, auth_token, status,
                         file_name, file_type, file_size)
                    VALUES (?, ?, ?, ?, ?, 'encrypted', ?, ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        original_hash = excluded.original_hash,
                        encrypted_path = excluded.encrypted_path,
                        file_key_encrypted = excluded.file_key_encrypted,
                        auth_token = excluded.auth_token,
                        status = 'encrypted',
                        file_name = excluded.file_name,
                        file_type = excluded.file_type,
                        file_size = excluded.file_size,
                        updated_at = datetime('now')
                    """,
                    (file_path, original_hash, encrypted_path,
                     file_key_encrypted, auth_token, file_name, file_type, file_size),
                )
                row_id = conn.execute(
                    "SELECT id FROM protected_files WHERE file_path = ?",
                    (file_path,),
                ).fetchone()["id"]
                conn.commit()
                logger.debug("Protected file added/updated: %s (id=%d)", file_path, row_id)
                return row_id

    def get_protected_file(self, file_path: str) -> dict[str, Any] | None:
        """Look up a protected file by original path."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM protected_files WHERE file_path = ?",
                    (file_path,),
                ).fetchone()
                return dict(row) if row else None

    def get_protected_file_by_name(self, file_name: str) -> dict[str, Any] | None:
        """Look up a protected file by file name."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM protected_files WHERE file_name = ?",
                    (file_name,),
                ).fetchone()
                return dict(row) if row else None

    def update_protected_file_status(self, file_path: str, status: str) -> None:
        """Update the status of a protected file."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE protected_files SET status = ?, updated_at = datetime('now') WHERE file_path = ?",
                    (status, file_path),
                )
                conn.commit()

    def list_protected_files(self, status: str | None = None) -> list[dict[str, Any]]:
        """Return all protected files, optionally filtered by status."""
        with self._lock:
            with self._connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM protected_files WHERE status = ? ORDER BY updated_at DESC",
                        (status,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM protected_files ORDER BY updated_at DESC",
                    ).fetchall()
                return [dict(r) for r in rows]

    def is_file_protected(self, file_path: str) -> bool:
        """Check whether a file is currently tracked as protected."""
        record = self.get_protected_file(file_path)
        return record is not None and record["status"] in ("encrypted", "pending")

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def add_device(
        self,
        device_name: str,
        device_id: str = "",
        device_type: str = "removable",
        mount_point: str = "",
        drive_letter: str = "",
        filesystem_type: str = "",
        total_size_bytes: int = 0,
    ) -> int:
        """Record a connected device. Returns row id."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO devices
                        (device_name, device_id, device_type, mount_point,
                         drive_letter, filesystem_type, total_size_bytes, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'connected')
                    """,
                    (device_name, device_id, device_type, mount_point,
                     drive_letter, filesystem_type, total_size_bytes),
                )
                conn.commit()
                logger.debug("Device added: %s at %s", device_name, mount_point)
                return cursor.lastrowid  # type: ignore[return-value]

    def get_device_by_mount(self, mount_point: str) -> dict[str, Any] | None:
        """Find the latest device entry for a given mount point."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM devices WHERE mount_point = ? ORDER BY last_seen DESC LIMIT 1",
                    (mount_point,),
                ).fetchone()
                return dict(row) if row else None

    def update_device_status(self, mount_point: str, status: str) -> None:
        """Update the status of all devices at a mount point."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE devices SET status = ?, last_seen = datetime('now') WHERE mount_point = ?",
                    (status, mount_point),
                )
                conn.commit()

    def list_devices(self, status: str | None = None) -> list[dict[str, Any]]:
        """Return all device records, optionally filtered by status."""
        with self._lock:
            with self._connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM devices WHERE status = ? ORDER BY last_seen DESC",
                        (status,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM devices ORDER BY last_seen DESC",
                    ).fetchall()
                return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Event Queue (offline resilience)
    # ------------------------------------------------------------------

    def add_event_to_queue(self, event_json: str) -> int:
        """Enqueue an event for later delivery. Returns row id."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO event_queue (event_json) VALUES (?)",
                    (event_json,),
                )
                conn.commit()
                return cursor.lastrowid  # type: ignore[return-value]

    def get_pending_events(self, limit: int = 25) -> list[dict[str, Any]]:
        """Retrieve pending events ordered by creation time."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM event_queue
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]

    def mark_event_sent(self, event_id: int) -> None:
        """Mark a queued event as successfully sent."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE event_queue SET status = 'sent', last_attempt = datetime('now') WHERE id = ?",
                    (event_id,),
                )
                conn.commit()

    def mark_event_failed(self, event_id: int) -> None:
        """Increment retry count and update last attempt timestamp."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE event_queue
                    SET retry_count = retry_count + 1,
                        last_attempt = datetime('now'),
                        status = CASE
                            WHEN retry_count + 1 >= 5 THEN 'failed'
                            ELSE 'pending'
                        END
                    WHERE id = ?
                    """,
                    (event_id,),
                )
                conn.commit()

    def get_queue_stats(self) -> dict[str, int]:
        """Return counts of events by status."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT status, COUNT(*) as count FROM event_queue GROUP BY status",
                ).fetchall()
                return {row["status"]: row["count"] for row in rows}

    def purge_sent_events(self) -> int:
        """Delete all events that have been successfully sent. Returns count deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM event_queue WHERE status = 'sent'")
                conn.commit()
                return cursor.rowcount

    # ------------------------------------------------------------------
    # Key Store
    # ------------------------------------------------------------------

    def store_key(self, file_name: str, encrypted_key_blob: str, auth_token: str = "") -> None:
        """Store an encrypted key blob for a file."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO key_store (file_name, encrypted_key_blob, auth_token)
                    VALUES (?, ?, ?)
                    ON CONFLICT(file_name) DO UPDATE SET
                        encrypted_key_blob = excluded.encrypted_key_blob,
                        auth_token = excluded.auth_token
                    """,
                    (file_name, encrypted_key_blob, auth_token),
                )
                conn.commit()

    def get_key(self, file_name: str) -> dict[str, Any] | None:
        """Retrieve key info for a file."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM key_store WHERE file_name = ?",
                    (file_name,),
                ).fetchone()
                return dict(row) if row else None

    # ------------------------------------------------------------------
    # Config Key-Value Store
    # ------------------------------------------------------------------

    def set_config(self, key: str, value: str) -> None:
        """Set a runtime configuration value."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO config_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
                conn.commit()

    def get_config(self, key: str, default: str = "") -> str:
        """Get a runtime configuration value."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT value FROM config_kv WHERE key = ?",
                    (key,),
                ).fetchone()
                return row["value"] if row else default

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Explicitly close (no-op for per-call connections, but logs shutdown)."""
        logger.info("LocalStore closed")
