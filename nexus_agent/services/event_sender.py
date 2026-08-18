"""
NEXUS Endpoint Agent — Resilient Event Sender.

Sends SecurityEvents to the SOC server with:
- Immediate delivery attempt
- Automatic queue-to-SQLite on failure
- Background thread to flush pending events
- Configurable retry count and backoff
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING

from core.models import SecurityEvent
from services.server_client import ServerClient, ServerError, ServerUnavailable
from utils.logging_config import get_logger

if TYPE_CHECKING:
    from config import NexusConfig
    from database.local_store import LocalStore

logger = get_logger(__name__)


class EventSender:
    """
    Delivers SecurityEvents to the SOC server with offline resilience.

    On ``send()``:
      1. Try immediate HTTP delivery.
      2. On failure, persist the event to the local SQLite queue.

    A background thread periodically flushes pending events from the
    queue, respecting retry limits and backoff.
    """

    def __init__(
        self,
        config: NexusConfig,
        server_client: ServerClient,
        local_store: LocalStore,
    ) -> None:
        self._config = config
        self._client = server_client
        self._store = local_store
        self._retry_delay = config.event_queue.retry_delay_seconds
        self._max_retries = config.event_queue.max_retries
        self._batch_size = config.event_queue.batch_size
        self._running = False
        self._flush_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        logger.info("EventSender initialized (retry_delay=%ds, max_retries=%d)",
                     self._retry_delay, self._max_retries)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, event: SecurityEvent) -> bool:
        """
        Send an event to the server, queuing on failure.

        Returns True if delivered immediately, False if queued.
        Only HIGH and MEDIUM severity events are sent.
        NORMAL events are dropped entirely.
        """
        # ---- Drop ALL NORMAL severity events ----
        # Only HIGH and MEDIUM events reach the server/dashboard.
        if event.severity.value.upper() == "NORMAL":
            logger.debug("Dropping NORMAL event: %s %s",
                         event.event_type.value, event.action)
            return False

        payload = event.to_server_payload()
        try:
            self._client.log_event(payload)
            logger.info("Event sent: %s [%s] %s",
                        event.event_type.value, event.severity.value, event.action)
            return True
        except (ServerUnavailable, ServerError) as exc:
            logger.warning("Event delivery failed, queuing: %s — %s", event.event_id, exc)
            self._queue_event(event)
            return False
        except Exception as exc:
            logger.error("Unexpected error sending event %s: %s", event.event_id, exc)
            self._queue_event(event)
            return False

    def start_background_flush(self) -> None:
        """Start the background thread that flushes pending events."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="nexus-event-flush",
            daemon=True,
        )
        self._flush_thread.start()
        logger.info("Background event flush started")

    def stop_background_flush(self) -> None:
        """Stop the background flush thread."""
        self._running = False
        self._stop_event.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=10)
        logger.info("Background event flush stopped")

    def flush_now(self) -> int:
        """
        Immediately attempt to send all pending events.

        Returns the number of events successfully sent.
        """
        return self._flush_pending()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _queue_event(self, event: SecurityEvent) -> None:
        """Persist an event to the local SQLite queue."""
        event_json = json.dumps(event.to_server_payload())
        self._store.add_event_to_queue(event_json)
        logger.debug("Event queued locally: %s", event.event_id)

    def _flush_loop(self) -> None:
        """Background thread: periodically flush pending events."""
        while not self._stop_event.is_set():
            try:
                sent = self._flush_pending()
                if sent > 0:
                    logger.info("Flushed %d queued events", sent)
            except Exception as exc:
                logger.error("Flush loop error: %s", exc)
            self._stop_event.wait(timeout=self._retry_delay)

    def _flush_pending(self) -> int:
        """Attempt to send all pending events from the queue. Returns count sent."""
        pending = self._store.get_pending_events(limit=self._batch_size)
        if not pending:
            return 0

        sent_count = 0
        for row in pending:
            try:
                payload = json.loads(row["event_json"])
                
                # Filter out any queued heartbeats from previous runs
                event_data = payload.get("event_data", {})
                if event_data.get("event_type") == "heartbeat" or "heartbeat" in payload.get("action", "").lower():
                    self._store.mark_event_sent(row["id"])
                    continue

                self._client.log_event(payload)
                self._store.mark_event_sent(row["id"])
                sent_count += 1
            except (ServerUnavailable, ServerError):
                self._store.mark_event_failed(row["id"])
            except Exception as exc:
                logger.error("Failed to flush event %d: %s", row["id"], exc)
                self._store.mark_event_failed(row["id"])

        # Clean up successfully sent events
        if sent_count > 0:
            self._store.purge_sent_events()

        return sent_count
