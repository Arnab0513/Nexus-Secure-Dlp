"""
NEXUS Decrypt — Standalone Decryption Core.

This module handles the complete .ndlp decryption pipeline:
  1. Parse the .ndlp JSON package
  2. Request the decryption key from the SOC server
  3. Fernet-decrypt the ciphertext
  4. Write the original file to disk
  5. Open the file with the system default application

This is a standalone module with NO dependencies on nexus_agent/ or server/.
It communicates with the server via HTTP REST API only.
"""

from __future__ import annotations

import base64
import json
import platform
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests
from cryptography.fernet import Fernet, InvalidToken


# ------------------------------------------------------------------
# Data types
# ------------------------------------------------------------------

@dataclass
class NdlpPackage:
    """Parsed .ndlp file contents."""
    original_name: str
    original_extension: str
    original_size: int
    original_hash: str
    ciphertext_b64: str
    created_by: str
    algorithm: str
    department_id: str
    source_path: Path


class DecryptionError(Exception):
    """Raised when decryption fails for any reason."""


class ServerAuthError(DecryptionError):
    """Raised when the server denies decryption (unauthorized)."""


class ServerConnectionError(DecryptionError):
    """Raised when the server cannot be reached."""


# ------------------------------------------------------------------
# Core functions
# ------------------------------------------------------------------

def get_device_name() -> str:
    """Return the hostname of this machine."""
    return socket.gethostname()


def parse_ndlp(file_path: str | Path) -> NdlpPackage:
    """
    Parse a .ndlp file and return a structured NdlpPackage.

    Raises DecryptionError if the file is invalid.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise DecryptionError(f"File not found: {path}")
    if not path.suffix == ".ndlp":
        raise DecryptionError(f"Not a .ndlp file: {path.name}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DecryptionError(f"Invalid .ndlp file format: {exc}") from exc

    required_keys = ["original_name", "ciphertext_b64"]
    for key in required_keys:
        if key not in raw:
            raise DecryptionError(f"Missing required field '{key}' in .ndlp file")

    return NdlpPackage(
        original_name=raw["original_name"],
        original_extension=raw.get("original_extension", ""),
        original_size=raw.get("original_size", 0),
        original_hash=raw.get("original_hash", ""),
        ciphertext_b64=raw["ciphertext_b64"],
        created_by=raw.get("created_by", "unknown"),
        algorithm=raw.get("algorithm", "AES-256-Fernet"),
        department_id=raw.get("department_id", ""),
        source_path=path,
    )


def capture_image_b64() -> str | None:
    """Capture an image from the webcam and return it as a base64 string."""
    import sys
    import os
    # Add project root to sys.path to ensure nexus_agent can be imported
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    try:
        from nexus_agent.services.camera_provider import get_camera_provider
        provider = get_camera_provider()
    except Exception as e:
        print(f"[INTRUDER] Webcam capture failed to initialize provider: {e}")
        return None
        
    print(f"[INTRUDER] Starting webcam capture via provider...")
    tmp_path = "/tmp/nexus_intruder_capture.jpg"
    
    result = provider.capture(tmp_path)
    
    if result.success:
        try:
            with open(tmp_path, "rb") as f:
                img_data = f.read()
            os.remove(tmp_path)
            print("[INTRUDER] Uploading evidence to server")
            return base64.b64encode(img_data).decode('utf-8')
        except Exception as e:
            print(f"[INTRUDER] Webcam capture failed to read image: {e}")
            return None
    else:
        print(f"[INTRUDER] Webcam capture failed: {result.error}")
        return None


def request_decryption_key(
    server_url: str,
    file_name: str,
    auth_token: str,
    department: str = "",
    device_name: str | None = None,
) -> str:
    """
    Request the decryption key from the SOC server.

    Returns the Fernet file_key on success.
    Raises ServerAuthError on 403, ServerConnectionError on network failure.
    """
    device = device_name or get_device_name()
    url = f"{server_url.rstrip('/')}/client/request-decryption"

    payload = {
        "device": device,
        "file_name": file_name,
        "auth_token": auth_token,
        "department": department,
    }

    try:
        resp = requests.post(url, json=payload, timeout=15)
    except requests.ConnectionError:
        raise ServerConnectionError(
            "Cannot connect to the NEXUS server.\n"
            f"Please ensure the server is running at:\n{server_url}"
        )
    except requests.Timeout:
        raise ServerConnectionError(
            "Server request timed out.\nPlease try again."
        )

    if resp.status_code == 403:
        try:
            print("[SECURITY] Creating unauthorized event")
            print("[SECURITY] Requesting client webcam capture")
            # Capture webcam image regardless of what the server says
            img_b64 = capture_image_b64()
            
            # Send the evidence to the logging endpoint
            log_url = f"{server_url.rstrip('/')}/client/log-event"
            log_payload = {
                "device": device,
                "file": file_name,
                "action": f"Unauthorized access attempt for {file_name}",
                "severity": "HIGH",
            }
            if img_b64:
                log_payload["intrusion_image_b64"] = img_b64
                
            try:
                print("[INTRUDER] Uploading evidence to server")
                log_resp = requests.post(log_url, json=log_payload, timeout=15)
                if log_resp.status_code == 200:
                    print("[INTRUDER] Evidence uploaded successfully")
            except Exception:
                pass # Ignore log delivery failures here, the user still gets 403
        except Exception:
            pass
            
        raise ServerAuthError("Wrong password. Access denied and intrusion logged.")

    if resp.status_code == 404:
        raise DecryptionError(
            "Package not found on the server.\n\n"
            "The encrypted file may have been created on a different\n"
            "server, or the package record has been removed."
        )

    if resp.status_code >= 400:
        raise DecryptionError(f"Server error (HTTP {resp.status_code})")

    data = resp.json()
    file_key = data.get("file_key", "")
    if not file_key:
        raise DecryptionError("Server returned an empty decryption key.")

    return file_key


def decrypt_data(file_key: str, ciphertext_b64: str) -> bytes:
    """
    Decrypt Fernet-encrypted data.

    Returns the plaintext bytes.
    """
    try:
        cipher = Fernet(file_key.encode())
        ciphertext = base64.b64decode(ciphertext_b64)
        return cipher.decrypt(ciphertext)
    except InvalidToken:
        raise DecryptionError(
            "Decryption failed — the key does not match this file.\n"
            "The file may be corrupted."
        )
    except Exception as exc:
        raise DecryptionError(f"Decryption error: {exc}")


def open_file(file_path: Path) -> None:
    """Open a file with the system default application."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.Popen(["open", str(file_path)])
        elif system == "Windows":
            subprocess.Popen(["start", "", str(file_path)], shell=True)
        else:  # Linux
            subprocess.Popen(["xdg-open", str(file_path)])
    except Exception:
        pass  # Silently fail — the file is still on disk


def decrypt_file(
    ndlp_path: str | Path,
    auth_token: str,
    server_url: str,
    output_dir: str | Path | None = None,
    auto_open: bool = True,
) -> Path:
    """
    Full decryption pipeline: parse → auth → decrypt → write → open.

    Parameters
    ----------
    ndlp_path : path to the .ndlp file
    auth_token : the authorization token for this package
    server_url : URL of the NEXUS SOC server
    output_dir : where to write the decrypted file (default: same folder as .ndlp)
    auto_open : whether to auto-open the decrypted file

    Returns
    -------
    Path to the decrypted file.

    Raises
    ------
    DecryptionError, ServerAuthError, ServerConnectionError
    """
    # 1. Parse the .ndlp file
    package = parse_ndlp(ndlp_path)

    # 2. Request key from server
    file_key = request_decryption_key(
        server_url=server_url,
        file_name=package.original_name,
        auth_token=auth_token,
        department=package.department_id,
    )

    # 3. Decrypt
    plaintext = decrypt_data(file_key, package.ciphertext_b64)

    # 4. Write original file
    out_dir = Path(output_dir) if output_dir else package.source_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / package.original_name

    # Handle name collision
    if out_path.exists():
        stem = out_path.stem
        suffix = out_path.suffix
        counter = 1
        while out_path.exists():
            out_path = out_dir / f"{stem} ({counter}){suffix}"
            counter += 1

    out_path.write_bytes(plaintext)

    # 5. Auto-open
    if auto_open:
        open_file(out_path)

    return out_path
