"""
NEXUS Endpoint Agent — Platform Information Utilities.

Provides OS-level identity information used in every SecurityEvent.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket


def get_hostname() -> str:
    """Return the machine hostname."""
    return socket.gethostname()


def get_username() -> str:
    """Return the currently logged-in OS username."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def get_local_ip() -> str:
    """
    Return the best-guess local IP address.

    Connects a UDP socket to an external address (no data sent)
    to determine which local interface the OS would choose.
    Falls back to 127.0.0.1 if no network is available.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_os_info() -> str:
    """Return a human-readable OS description."""
    return f"{platform.system()} {platform.release()} ({platform.machine()})"
