"""
NEXUS Endpoint Agent — Encryption Engine.

AES-256-Fernet file encryption and decryption with server-managed keys.

Workflow:
  encrypt_file  → request key from server → Fernet encrypt → write .ndlp → store in DB
  decrypt_file  → verify token with server → Fernet decrypt → write original file
  re_encrypt    → re-encrypt a temporarily-decrypted file using the stored key
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken

from core.models import EventType, SecurityEvent, Severity
from services.server_client import ServerClient, ServerError, ServerUnavailable
from utils.logging_config import get_logger
from utils.platform_info import get_hostname, get_local_ip, get_username

if TYPE_CHECKING:
    from config import NexusConfig
    from database.local_store import LocalStore
    from services.event_sender import EventSender

logger = get_logger(__name__)

# Extension appended to encrypted files
ENCRYPTED_EXTENSION = ".ndlp"


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


class EncryptionEngine:
    """
    Manages the full encrypt → decrypt → re-encrypt lifecycle.

    Keys are never stored in plaintext on disk.  The server issues
    Fernet keys via ``/client/request-encryption``, and the agent
    stores only the encrypted key blob and auth token in the local DB.
    """

    def __init__(
        self,
        config: NexusConfig,
        server_client: ServerClient,
        local_store: LocalStore,
        event_sender: EventSender,
    ) -> None:
        self._config = config
        self._client = server_client
        self._store = local_store
        self._sender = event_sender
        self._device = config.device.resolved_name()
        logger.info("EncryptionEngine initialized")

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt_file(self, file_path: str | Path, department: str | None = None) -> Path | None:
        """
        Encrypt a file and produce a ``.ndlp`` package.

        Steps:
          1. Validate the file (exists, not already encrypted, monitored extension).
          2. Request an encryption key from the server.
          3. Read plaintext → Fernet encrypt.
          4. Write ``.ndlp`` JSON package.
          5. Store package metadata in local DB.
          6. Emit FILE_ENCRYPTED event.
          7. Remove the original plaintext file.

        Returns the path to the ``.ndlp`` file, or ``None`` on failure.
        """
        file_path = Path(file_path).resolve()

        # --- Validation ---
        if not file_path.exists():
            logger.error("File does not exist: %s", file_path)
            return None
        if file_path.suffix == ENCRYPTED_EXTENSION:
            logger.warning("File is already encrypted: %s", file_path)
            return None
        if not self._config.monitoring.is_monitored_extension(file_path.suffix):
            logger.info("Skipping non-monitored extension: %s", file_path.suffix)
            return None
        if self._store.is_file_protected(str(file_path)):
            logger.info("File already protected: %s", file_path)
            return None

        try:
            # --- Extract Department from Filename ---
            # e.g. "Test File.DA.txt" -> stem: "Test File.DA" -> suffix: ".txt"
            parts = file_path.stem.split('.')
            if len(parts) < 2:
                logger.error("Filename %s does not contain a department marker. Expected format: name.DEPT.ext", file_path.name)
                return None
                
            extracted_department = parts[-1].upper()
            if extracted_department not in ("DA", "DB"):
                logger.error("Unrecognized department marker '%s' in filename %s", extracted_department, file_path.name)
                return None
                
            logger.info("Extracted department %s from filename %s", extracted_department, file_path.name)
            department = extracted_department

            # --- Read plaintext ---
            plaintext = file_path.read_bytes()
            original_hash = _sha256(plaintext)
            file_size = len(plaintext)

            # --- Request key from server ---
            enc_resp = self._client.request_encryption(file_path.name, department=department)
            file_key = enc_resp.file_key
            department_assigned = enc_resp.department

            # --- Encrypt ---
            cipher = Fernet(file_key.encode())
            ciphertext = cipher.encrypt(plaintext)

            # --- Build .ndlp package ---
            package_data = {
                "original_name": file_path.name,
                "original_extension": file_path.suffix,
                "original_size": file_size,
                "original_hash": original_hash,
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                "created_by": self._device,
                "algorithm": self._config.encryption.algorithm,
                "department_id": department_assigned,
                "key_version": enc_resp.key_version,
            }

            out_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_EXTENSION)
            out_path.write_text(json.dumps(package_data, indent=2), encoding="utf-8")

            # --- Store in local DB ---
            self._store.add_protected_file(
                file_path=str(file_path),
                original_hash=original_hash,
                encrypted_path=str(out_path),
                file_key_encrypted=file_key,  # Stored locally; server also keeps copy
                auth_token=department_assigned,
                file_name=file_path.name,
                file_type=file_path.suffix,
                file_size=file_size,
            )
            self._store.store_key(file_path.name, file_key, department_assigned)

            # --- Remove original plaintext ---
            file_path.unlink()

            # --- Emit event ---
            self._sender.send(SecurityEvent(
                event_type=EventType.FILE_ENCRYPTED,
                severity=Severity.NORMAL,
                action=f"Encrypted {file_path.name}",
                device_name=self._device,
                computer_name=get_hostname(),
                username=get_username(),
                ip_address=get_local_ip(),
                file_name=file_path.name,
                file_type=file_path.suffix,
                file_path=str(file_path),
                file_size=file_size,
                status="encrypted",
            ))

            logger.info("Encrypted %s → %s", file_path.name, out_path.name)
            return out_path

        except (ServerUnavailable, ServerError) as exc:
            logger.error("Server error during encryption of %s: %s", file_path.name, exc)
            self._sender.send(SecurityEvent(
                event_type=EventType.FILE_ENCRYPTED,
                severity=Severity.HIGH,
                action=f"Encryption failed for {file_path.name}: {exc}",
                device_name=self._device,
                file_name=file_path.name,
                file_path=str(file_path),
                status="failed",
            ))
            return None
        except Exception as exc:
            logger.error("Unexpected error encrypting %s: %s", file_path.name, exc, exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt_file(
        self,
        ndlp_path: str | Path,
        auth_token: str | None = None,
        output_dir: str | Path | None = None,
    ) -> Path | None:
        """
        Decrypt a ``.ndlp`` package back to the original file.

        Steps:
          1. Parse the ``.ndlp`` JSON.
          2. Look up auth_token in local DB (or use provided token).
          3. Request decryption key from server (validates authorization).
          4. Fernet decrypt.
          5. Write the original file.
          6. Emit FILE_DECRYPTED event.

        On authorization failure (HTTP 403), returns ``None`` and the
        caller should trigger intruder capture externally.

        Returns the path to the decrypted file, or ``None`` on failure.
        """
        ndlp_path = Path(ndlp_path).resolve()

        if not ndlp_path.exists():
            logger.error("Package file does not exist: %s", ndlp_path)
            return None

        try:
            package = json.loads(ndlp_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("Invalid .ndlp package: %s — %s", ndlp_path, exc)
            return None

        file_name = package.get("original_name", "unknown")
        ciphertext_b64 = package.get("ciphertext_b64", "")

        # --- Resolve auth token ---
        if not auth_token:
            key_record = self._store.get_key(file_name)
            if key_record:
                auth_token = key_record.get("auth_token", "")
        if not auth_token:
            db_record = self._store.get_protected_file_by_name(file_name)
            if db_record:
                auth_token = db_record.get("auth_token", "")

        if not auth_token:
            logger.error("No auth token available for file %s", file_name)
            return None

        try:
            # --- Request decryption from server ---
            dec_resp = self._client.request_decryption(
                auth_token=auth_token,
                file_name=file_name,
            )
            file_key = dec_resp.file_key

            # --- Decrypt ---
            cipher = Fernet(file_key.encode())
            plaintext = cipher.decrypt(base64.b64decode(ciphertext_b64))

            # --- Write original file ---
            out_dir = Path(output_dir) if output_dir else ndlp_path.parent
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / file_name
            out_path.write_bytes(plaintext)

            # --- Update local DB ---
            self._store.update_protected_file_status(str(out_path), "decrypted")

            # --- Emit event ---
            self._sender.send(SecurityEvent(
                event_type=EventType.FILE_DECRYPTED,
                severity=Severity.MEDIUM,
                action=f"Decrypted file {file_name}",
                device_name=self._device,
                computer_name=get_hostname(),
                username=get_username(),
                ip_address=get_local_ip(),
                file_name=file_name,
                file_path=str(out_path),
                file_size=len(plaintext),
                status="decrypted",
            ))

            logger.info("Decrypted %s → %s", ndlp_path.name, out_path)
            return out_path

        except ServerError as exc:
            severity = Severity.HIGH
            event_type = EventType.WRONG_PASSWORD
            action = f"Decryption denied for file {file_name}: {exc.detail}"

            self._sender.send(SecurityEvent(
                event_type=event_type,
                severity=severity,
                action=action,
                device_name=self._device,
                computer_name=get_hostname(),
                username=get_username(),
                ip_address=get_local_ip(),
                file_name=file_name,
                file_path=str(ndlp_path),
                status="denied",
            ))
            logger.warning("Decryption denied for %s: %s", file_name, exc)
            return None

        except ServerUnavailable as exc:
            logger.error("Server unavailable for decryption: %s", exc)
            return None

        except InvalidToken:
            logger.error("Invalid encryption key — file may be corrupted: %s", ndlp_path)
            return None

        except Exception as exc:
            logger.error("Unexpected error decrypting %s: %s", ndlp_path, exc, exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Re-encrypt
    # ------------------------------------------------------------------

    def re_encrypt_file(self, file_path: str | Path, file_name: str) -> Path | None:
        """
        Re-encrypt a temporarily decrypted file using the stored key.

        This is called after a user finishes viewing a decrypted file,
        to ensure the plaintext does not remain on disk.

        Returns the path to the re-encrypted ``.ndlp`` file, or ``None``.
        """
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            logger.error("File to re-encrypt does not exist: %s", file_path)
            return None

        key_record = self._store.get_key(file_name)
        if not key_record:
            logger.error("No stored key for file %s — cannot re-encrypt", file_name)
            return None

        try:
            file_key = key_record["encrypted_key_blob"]
            plaintext = file_path.read_bytes()

            cipher = Fernet(file_key.encode())
            ciphertext = cipher.encrypt(plaintext)

            # Rebuild .ndlp package
            db_record = self._store.get_protected_file_by_name(file_name)
            package_data = {
                "original_name": file_path.name,
                "original_extension": file_path.suffix,
                "original_size": len(plaintext),
                "original_hash": _sha256(plaintext),
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                "created_by": self._device,
                "algorithm": self._config.encryption.algorithm,
                "department_id": db_record.get("auth_token", "unknown") if db_record else "unknown",
            }

            out_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_EXTENSION)
            out_path.write_text(json.dumps(package_data, indent=2), encoding="utf-8")

            # Remove plaintext
            file_path.unlink()

            # Update DB
            if db_record:
                self._store.update_protected_file_status(db_record["file_path"], "encrypted")

            self._sender.send(SecurityEvent(
                event_type=EventType.FILE_ENCRYPTED,
                severity=Severity.NORMAL,
                action=f"Re-encrypted {file_path.name}",
                device_name=self._device,
                computer_name=get_hostname(),
                username=get_username(),
                ip_address=get_local_ip(),
                file_name=file_path.name,
                file_path=str(file_path),
                file_size=len(plaintext),
                status="re-encrypted",
            ))

            logger.info("Re-encrypted %s → %s", file_path.name, out_path.name)
            return out_path

        except Exception as exc:
            logger.error("Re-encryption failed for %s: %s", file_path, exc, exc_info=True)
            return None
