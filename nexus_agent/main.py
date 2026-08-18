"""
NEXUS Endpoint Agent — Main Orchestrator.

Wires all modules together and provides the single entry point
for the NEXUS Endpoint Security Platform.

Usage:
    python main.py                      Run the agent (continuous)
    python main.py encrypt <file>       Encrypt a single file
    python main.py decrypt <file.ndlp>  Decrypt a single package
    python main.py status               Show agent status
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path

# Ensure the agent directory is on sys.path
_AGENT_DIR = Path(__file__).resolve().parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from config import NexusConfig
from core.device_monitor import create_device_monitor
from core.encryption_engine import EncryptionEngine
from core.file_monitor import FileMonitor
from core.intruder_capture import IntruderCapture
from core.models import EventType, SecurityEvent, Severity
from database.local_store import LocalStore
from services.event_sender import EventSender
from services.server_client import ServerClient, ServerUnavailable
from utils.logging_config import get_logger, setup_logging
from utils.platform_info import get_hostname, get_local_ip, get_os_info, get_username

logger = get_logger(__name__)

# ------------------------------------------------------------------
# PID file management — prevents zombie processes
# ------------------------------------------------------------------

_PID_FILE = _AGENT_DIR / "nexus_agent.pid"


class PidManager:
    """
    Manages a PID file to ensure only one agent instance runs at a time.

    On ``acquire()``:
      1. If a PID file exists, check whether the process is still alive.
      2. If alive, send SIGTERM and wait for it to exit.
      3. Write the current PID to the file.

    On ``release()``:
      Remove the PID file.
    """

    @staticmethod
    def acquire() -> None:
        """Claim the PID file, killing any stale agent first."""
        PidManager._kill_stale()
        _PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        logger.info("PID file written: %s (pid=%d)", _PID_FILE, os.getpid())

    @staticmethod
    def release() -> None:
        """Remove the PID file on shutdown."""
        try:
            if _PID_FILE.exists():
                _PID_FILE.unlink()
                logger.info("PID file removed: %s", _PID_FILE)
        except OSError as exc:
            logger.warning("Could not remove PID file: %s", exc)

    @staticmethod
    def read_pid() -> int | None:
        """Read the PID from the file, or None if missing/invalid."""
        try:
            return int(_PID_FILE.read_text(encoding="utf-8").strip())
        except (FileNotFoundError, ValueError):
            return None

    @staticmethod
    def is_running(pid: int) -> bool:
        """Check if a process with the given PID is alive."""
        try:
            os.kill(pid, 0)  # Signal 0 = existence check, no actual signal
            return True
        except (OSError, ProcessLookupError):
            return False

    @staticmethod
    def _kill_stale() -> None:
        """If a previous agent is still running, terminate it."""
        pid = PidManager.read_pid()
        if pid is None:
            return
        if pid == os.getpid():
            return
        if not PidManager.is_running(pid):
            logger.info("Stale PID file found (pid=%d not running), removing", pid)
            PidManager.release()
            return

        logger.warning("Another agent is running (pid=%d) — sending SIGTERM", pid)
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait up to 10 seconds for graceful shutdown
            for _ in range(20):
                time.sleep(0.5)
                if not PidManager.is_running(pid):
                    logger.info("Previous agent (pid=%d) has exited", pid)
                    break
            else:
                # Force kill if still alive
                logger.warning("Force-killing previous agent (pid=%d)", pid)
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.5)
        except (OSError, ProcessLookupError):
            pass  # Process already exited
        PidManager.release()

    @staticmethod
    def stop_running_agent() -> bool:
        """
        Stop any running agent found via the PID file.

        Returns True if an agent was found and stopped, False otherwise.
        """
        pid = PidManager.read_pid()
        if pid is None:
            print("[INFO] No PID file found — no agent appears to be running.")
            return False
        if not PidManager.is_running(pid):
            print(f"[INFO] PID file found (pid={pid}) but process is not running. Cleaning up.")
            PidManager.release()
            return False

        print(f"[STOP] Sending SIGTERM to agent (pid={pid})...")
        try:
            os.kill(pid, signal.SIGTERM)
            for i in range(20):
                time.sleep(0.5)
                if not PidManager.is_running(pid):
                    print(f"[OK] Agent (pid={pid}) stopped gracefully.")
                    PidManager.release()
                    return True
            # Force kill
            print(f"[WARN] Agent not responding, sending SIGKILL to pid={pid}...")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            PidManager.release()
            print(f"[OK] Agent (pid={pid}) force-killed.")
            return True
        except (OSError, ProcessLookupError):
            print(f"[INFO] Agent (pid={pid}) already exited.")
            PidManager.release()
            return True


class NexusAgent:
    """
    Central orchestrator that initializes and manages all NEXUS modules.

    Lifecycle: ``__init__`` → ``start()`` → runs until SIGINT → ``stop()``.
    """

    def __init__(self, config: NexusConfig) -> None:
        self._config = config
        self._device_name = config.device.resolved_name()
        self._running = False
        self._stop_event = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

        # --- Initialize modules in dependency order ---
        self._store = LocalStore()
        self._client = ServerClient(config)
        self._sender = EventSender(config, self._client, self._store)
        self._engine = EncryptionEngine(config, self._client, self._store, self._sender)
        self._intruder = IntruderCapture(config, self._sender)
        self._file_monitor = FileMonitor(config, self._engine, self._sender, self._store)
        self._device_monitor = create_device_monitor(
            config, self._sender, self._store, self._file_monitor,
        )

        logger.info("NexusAgent initialized on %s (%s)", self._device_name, get_os_info())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the agent and all monitoring services."""
        if self._running:
            logger.warning("Agent is already running")
            return

        # Acquire PID lock — kills any stale zombie agent first
        PidManager.acquire()

        self._running = True
        logger.info("=" * 60)
        logger.info("  NEXUS Endpoint Agent starting")
        logger.info("  Device: %s", self._device_name)
        logger.info("  User:   %s", get_username())
        logger.info("  IP:     %s", get_local_ip())
        logger.info("  OS:     %s", get_os_info())
        logger.info("  Server: %s", self._config.server.url)
        logger.info("=" * 60)

        # --- Enroll with server ---
        self._enroll()

        # --- Start background services ---
        self._sender.start_background_flush()
        self._file_monitor.start()
        self._device_monitor.start()
        self._start_heartbeat()

        # --- Emit AGENT_STARTED ---
        self._sender.send(SecurityEvent(
            event_type=EventType.AGENT_STARTED,
            severity=Severity.NORMAL,
            action=f"NEXUS Agent started on {self._device_name}",
            device_name=self._device_name,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
            remarks=f"os={get_os_info()}",
        ))

        logger.info("NEXUS Agent is now running. Press Ctrl+C to stop.")
        logger.info("Monitoring: %s", self._file_monitor.watched_paths)

    def stop(self) -> None:
        """Gracefully stop the agent and all services."""
        if not self._running:
            return

        logger.info("Shutting down NEXUS Agent...")
        self._running = False
        self._stop_event.set()

        # Stop services in reverse order
        self._device_monitor.stop()
        self._file_monitor.stop()

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)

        # Emit AGENT_STOPPED event
        self._sender.send(SecurityEvent(
            event_type=EventType.AGENT_STOPPED,
            severity=Severity.NORMAL,
            action=f"NEXUS Agent stopped on {self._device_name}",
            device_name=self._device_name,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
        ))

        # Flush remaining events and deregister session
        self._sender.flush_now()
        self._sender.stop_background_flush()
        self._client.deregister()
        self._store.close()

        # Release PID file
        PidManager.release()

        logger.info("NEXUS Agent stopped.")

    def wait(self) -> None:
        """Block until a stop signal is received."""
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # One-shot operations
    # ------------------------------------------------------------------

    def encrypt_file(self, file_path: str, department: str | None = None) -> Path | None:
        """Encrypt a single file (one-shot, non-daemon mode)."""
        self._enroll()
        result = self._engine.encrypt_file(file_path, department=department)
        self._sender.flush_now()
        return result

    def decrypt_file(self, ndlp_path: str, auth_token: str | None = None) -> Path | None:
        """Decrypt a single package (one-shot, non-daemon mode)."""
        self._enroll()
        result = self._engine.decrypt_file(ndlp_path, auth_token=auth_token)
        self._sender.flush_now()
        return result

    def status(self) -> dict:
        """Return current agent status information."""
        files = self._store.list_protected_files()
        devices = self._store.list_devices()
        queue_stats = self._store.get_queue_stats()
        server_up = self._client.is_available()

        info = {
            "device_name": self._device_name,
            "username": get_username(),
            "ip_address": get_local_ip(),
            "os": get_os_info(),
            "server_url": self._config.server.url,
            "server_reachable": server_up,
            "protected_files": len(files),
            "encrypted_files": len([f for f in files if f["status"] == "encrypted"]),
            "known_devices": len(devices),
            "event_queue": queue_stats,
            "watched_paths": self._file_monitor.watched_paths if self._running else [],
        }
        return info

    # ------------------------------------------------------------------
    # Internal services
    # ------------------------------------------------------------------

    def _enroll(self) -> None:
        """Attempt server enrollment, log but don't crash on failure."""
        try:
            result = self._client.enroll()
            logger.info("Enrolled with server: %s", result.server_time)
        except ServerUnavailable:
            logger.warning("Server unreachable — will retry enrollment on next event")
        except Exception as exc:
            logger.error("Enrollment error: %s", exc)

    def _start_heartbeat(self) -> None:
        """Start the periodic heartbeat thread."""
        interval = self._config.heartbeat.interval_seconds
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="nexus-heartbeat",
            daemon=True,
            args=(interval,),
        )
        self._heartbeat_thread.start()
        logger.info("Heartbeat started (interval=%ds)", interval)

    def _heartbeat_loop(self, interval: int) -> None:
        """Send periodic heartbeat events to the server."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=interval)
            if self._stop_event.is_set():
                break
            try:
                files = self._store.list_protected_files()
                self._sender.send(SecurityEvent(
                    event_type=EventType.HEARTBEAT,
                    severity=Severity.NORMAL,
                    action=f"Heartbeat | files={len(files)} | paths={len(self._file_monitor.watched_paths)}",
                    device_name=self._device_name,
                    computer_name=get_hostname(),
                    username=get_username(),
                    ip_address=get_local_ip(),
                    remarks=f"protected_files={len(files)}",
                ))
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="nexus-agent",
        description="NEXUS Endpoint Data Protection Agent",
    )
    sub = parser.add_subparsers(dest="command")

    # Default: run the agent
    sub.add_parser("run", help="Run the agent in continuous monitoring mode")

    # Encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a single file")
    enc.add_argument("file", help="Path to the file to encrypt")
    enc.add_argument("--department", default=None, help="Department for this file (DA or DB)")

    # Decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a .ndlp package")
    dec.add_argument("file", help="Path to the .ndlp file")
    dec.add_argument("--token", default=None, help="Server-issued auth token")

    # Status
    sub.add_parser("status", help="Show agent status")

    # Stop a running agent
    sub.add_parser("stop", help="Stop a running agent process")

    return parser


def main() -> None:
    """Entry point for the NEXUS Endpoint Agent."""
    parser = _build_parser()
    args = parser.parse_args()
    command = args.command or "run"

    # Load config and setup logging
    config = NexusConfig.load()
    setup_logging(config.logging)

    errors = config.validate()
    if errors:
        for err in errors:
            print(f"[CONFIG ERROR] {err}", file=sys.stderr)
        sys.exit(1)

    agent = NexusAgent(config)

    if command == "stop":
        # Stop command doesn't need a full agent — just kill via PID file
        PidManager.stop_running_agent()
        sys.exit(0)

    if command == "run":
        # Register signal handlers for graceful shutdown
        def _signal_handler(signum, frame):
            logger.info("Received signal %d — initiating shutdown", signum)
            agent.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        agent.start()
        agent.wait()

    elif command == "encrypt":
        result = agent.encrypt_file(args.file, department=args.department)
        if result:
            print(f"[OK] Encrypted → {result}")
        else:
            print("[FAILED] Encryption failed — see logs for details", file=sys.stderr)
            sys.exit(1)

    elif command == "decrypt":
        result = agent.decrypt_file(args.file, auth_token=args.token)
        if result:
            print(f"[OK] Decrypted → {result}")
        else:
            print("[FAILED] Decryption failed — see logs for details", file=sys.stderr)
            sys.exit(1)

    elif command == "status":
        info = agent.status()
        print()
        print("╔══════════════════════════════════════════╗")
        print("║       NEXUS Endpoint Agent Status        ║")
        print("╠══════════════════════════════════════════╣")
        print(f"║  Device:      {info['device_name'][:26]:26s} ║")
        print(f"║  User:        {info['username'][:26]:26s} ║")
        print(f"║  IP:          {info['ip_address'][:26]:26s} ║")
        print(f"║  OS:          {info['os'][:26]:26s} ║")
        print(f"║  Server:      {info['server_url'][:26]:26s} ║")
        print(f"║  Reachable:   {'Yes' if info['server_reachable'] else 'No':26s} ║")
        print(f"║  Protected:   {str(info['protected_files']) + ' files':26s} ║")
        print(f"║  Encrypted:   {str(info['encrypted_files']) + ' files':26s} ║")
        print(f"║  Devices:     {str(info['known_devices']):26s} ║")
        print(f"║  Queue:       {str(info['event_queue']):26s} ║")
        print("╚══════════════════════════════════════════╝")
        print()


if __name__ == "__main__":
    main()
