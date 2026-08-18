"""
NEXUS Endpoint Agent — End User Secure File Decryption UI.

A modern customtkinter application allowing non-technical users
to decrypt .ndlp packages by providing the Decryption Key.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import TYPE_CHECKING, Any

# pyrefly: ignore [missing-import]
import customtkinter as ctk

from core.models import EventType, SecurityEvent, Severity
from utils.logging_config import get_logger
from utils.platform_info import get_hostname, get_local_ip, get_username

if TYPE_CHECKING:
    from config import NexusConfig
    from core.encryption_engine import EncryptionEngine
    from services.event_sender import EventSender

logger = get_logger(__name__)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DecryptApp(ctk.CTk):
    """
    Standalone GUI Application for decrypting NEXUS .ndlp packages.
    """

    def __init__(
        self,
        config: NexusConfig,
        encryption_engine: EncryptionEngine,
        event_sender: EventSender,
    ) -> None:
        super().__init__()

        self.config = config
        self.engine = encryption_engine
        self.sender = event_sender
        self.device_name = config.device.resolved_name()
        
        self.selected_file: Path | None = None

        # UI Configuration
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.title("NEXUS Secure File Access")
        self.geometry("650x450")
        self.resizable(False, False)

        # Build UI
        self._build_ui()

    def _build_ui(self) -> None:
        # Title
        self.lbl_title = ctk.CTkLabel(
            self, text="NEXUS Secure File Access", font=ctk.CTkFont(size=24, weight="bold")
        )
        self.lbl_title.pack(pady=(30, 20))

        # Encrypted File Section
        self.frame_file = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_file.pack(fill="x", padx=40, pady=10)
        
        self.lbl_file_header = ctk.CTkLabel(
            self.frame_file, text="Encrypted Package (.ndlp)", font=ctk.CTkFont(size=14)
        )
        self.lbl_file_header.pack(anchor="w", pady=(0, 5))

        self.frame_file_inner = ctk.CTkFrame(self.frame_file, fg_color="transparent")
        self.frame_file_inner.pack(fill="x")
        
        self.btn_browse = ctk.CTkButton(
            self.frame_file_inner, text="Browse", width=100, command=self._browse_file
        )
        self.btn_browse.pack(side="left", padx=(0, 10))
        
        self.lbl_selected_file = ctk.CTkLabel(
            self.frame_file_inner, text="No file selected", text_color="gray"
        )
        self.lbl_selected_file.pack(side="left")

        # Decryption Key Section
        self.frame_key = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_key.pack(fill="x", padx=40, pady=20)
        
        self.lbl_key_header = ctk.CTkLabel(
            self.frame_key, text="Decryption Key", font=ctk.CTkFont(size=14)
        )
        self.lbl_key_header.pack(anchor="w", pady=(0, 5))

        self.entry_key = ctk.CTkEntry(
            self.frame_key, placeholder_text="Enter the decryption key provided by authority...",
            show="*", height=40
        )
        self.entry_key.pack(fill="x")

        # Decrypt Button
        self.btn_decrypt = ctk.CTkButton(
            self, text="Decrypt File", height=45, font=ctk.CTkFont(size=16, weight="bold"),
            command=self._on_decrypt_clicked
        )
        self.btn_decrypt.pack(fill="x", padx=40, pady=20)

        # Status & Progress
        self.progress_bar = ctk.CTkProgressBar(self, mode="indeterminate")
        self.progress_bar.set(0)
        
        self.lbl_status = ctk.CTkLabel(
            self, text="Ready", text_color="gray", font=ctk.CTkFont(size=12)
        )
        self.lbl_status.pack(side="bottom", pady=20)

    def _browse_file(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Select NEXUS Encrypted Package",
            filetypes=[("NEXUS Package", "*.ndlp")]
        )
        if filepath:
            self.selected_file = Path(filepath)
            self.lbl_selected_file.configure(text=self.selected_file.name, text_color="white")

    def _set_loading_state(self, loading: bool, message: str = "") -> None:
        if loading:
            self.btn_decrypt.configure(state="disabled")
            self.btn_browse.configure(state="disabled")
            self.entry_key.configure(state="disabled")
            self.progress_bar.pack(fill="x", padx=40, pady=(0, 10))
            self.progress_bar.start()
            self.lbl_status.configure(text=message, text_color="white")
        else:
            self.btn_decrypt.configure(state="normal")
            self.btn_browse.configure(state="normal")
            self.entry_key.configure(state="normal")
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            self.lbl_status.configure(text=message, text_color="gray")

    def _emit_event(self, event_type: EventType, action: str, severity: Severity = Severity.NORMAL, **extra: Any) -> None:
        file_name = self.selected_file.name if self.selected_file else "unknown"
        file_path = str(self.selected_file) if self.selected_file else "unknown"
        
        self.sender.send(SecurityEvent(
            event_type=event_type,
            severity=severity,
            action=action,
            device_name=self.device_name,
            computer_name=get_hostname(),
            username=get_username(),
            ip_address=get_local_ip(),
            file_name=file_name,
            file_path=file_path,
            **extra
        ))

    def _on_decrypt_clicked(self) -> None:
        if not self.selected_file:
            messagebox.showwarning("Missing File", "Please select a .ndlp file to decrypt.")
            return
            
        auth_token = self.entry_key.get().strip()
        if not auth_token:
            messagebox.showwarning("Missing Key", "Please enter the decryption key.")
            return

        self._set_loading_state(True, "Contacting NEXUS Server for authorization...")
        self._emit_event(EventType.FILE_OPENED, "Decryption Requested for package", status="requested")

        # Run in background thread to prevent UI freeze
        threading.Thread(target=self._process_decryption, args=(self.selected_file, auth_token), daemon=True).start()

    def _process_decryption(self, ndlp_path: Path, auth_token: str) -> None:
        # Pre-validate the package format to catch corruption before hitting the server
        try:
            package_data = json.loads(ndlp_path.read_text(encoding="utf-8"))
            expected_hash = package_data.get("original_hash")
            original_name = package_data.get("original_name", "unknown")
            ciphertext_b64 = package_data.get("ciphertext_b64")
            department_id = package_data.get("department_id", "")
        except Exception as exc:
            logger.error("Package parsing failed: %s", exc)
            self._emit_event(EventType.UNAUTHORIZED_DEVICE, f"Package Tampered or Corrupted: {exc}", severity=Severity.HIGH, status="corrupted")
            self.after(0, self._set_loading_state, False, "Failed")
            self.after(0, lambda: messagebox.showerror("Corrupted Package", "This file is not a valid NEXUS encrypted package or has been tampered with."))
            return

        # Attempt Decryption by contacting server
        try:
            import requests
            
            url = f"{self.config.server.url.rstrip('/')}/client/request-decryption"
            payload = {
                "device": self.device_name,
                "password": auth_token,
                "file_name": original_name,
                "ciphertext_b64": ciphertext_b64,
                "original_name": original_name,
                "department": department_id
            }
                
            resp = requests.post(url, data=payload)
            
            if resp.status_code == 403:
                # Capture intruder image locally
                try:
                    from core.intruder_capture import IntruderCapture
                    import base64
                    intruder = IntruderCapture(self.config, None)
                    image_path, face_label = intruder.capture()
                    
                    b64_img = None
                    if image_path:
                        with open(image_path, "rb") as img_f:
                            b64_img = base64.b64encode(img_f.read()).decode('utf-8')
                            
                    self._emit_event(
                        EventType.WRONG_PASSWORD, 
                        f"Unauthorized access attempt for {original_name}", 
                        severity=Severity.HIGH, 
                        status="denied",
                        intrusion_image_b64=b64_img
                    )
                except Exception as e:
                    logger.error("Failed to capture intruder or emit event: %s", e)
                
                self.after(0, self._set_loading_state, False, "Access Denied")
                self.after(0, lambda: messagebox.showerror("Access Denied", "Incorrect password or unauthorized department."))
                return

            if resp.status_code == 200:
                if not resp.content:
                    self.after(0, self._set_loading_state, False, "Decryption Error")
                    self.after(0, lambda: messagebox.showerror("Error", "Server returned an empty response."))
                    return

                # server returned the file
                restored_path = ndlp_path.parent / original_name
                
                # handle name collision
                counter = 1
                while restored_path.exists():
                    stem = Path(original_name).stem
                    suffix = Path(original_name).suffix
                    restored_path = ndlp_path.parent / f"{stem} ({counter}){suffix}"
                    counter += 1

                restored_path.write_bytes(resp.content)
                
                # Open automatically on macOS
                import os
                os.system(f'open "{restored_path}"')
            else:
                self.after(0, self._set_loading_state, False, "Decryption Denied")
                try:
                    msg = resp.json().get("message") or resp.json().get("action")
                except:
                    msg = "Invalid Decryption Key or Unauthorized Device."
                self.after(0, lambda: messagebox.showerror("Decryption Denied", msg))
                return
        except Exception as exc:
            # Catch network timeouts or unexpected errors
            self._emit_event(EventType.UNAUTHORIZED_DEVICE, f"Network or server error during decryption: {exc}", severity=Severity.HIGH, status="error")
            self.after(0, self._set_loading_state, False, "Server Error")
            self.after(0, lambda: messagebox.showerror("Server Error", "Could not contact NEXUS Server. Please check your network connection."))
            return

        # --- Locally Verify Integrity Hash ---
        try:
            plaintext = restored_path.read_bytes()
            actual_hash = _sha256(plaintext)
            
            if expected_hash and actual_hash != expected_hash:
                # Tampered!
                logger.error("Integrity check failed. Expected %s, got %s", expected_hash, actual_hash)
                
                # Instantly destroy the tampered plaintext
                restored_path.unlink(missing_ok=True)
                
                self._emit_event(
                    EventType.INTEGRITY_VIOLATION, 
                    f"Integrity Check Failed for file {original_name}", 
                    severity=Severity.HIGH, 
                    status="tampered"
                )
                
                self.after(0, self._set_loading_state, False, "Integrity Check Failed")
                self.after(0, lambda: messagebox.showerror("Security Alert", "Integrity Check Failed!\n\nThe decrypted file did not match the original hash. The plaintext has been destroyed."))
                return
        except Exception as exc:
            logger.error("Failed to verify integrity: %s", exc)

        # Success!
        # Optional: Remove the .ndlp file
        try:
            ndlp_path.unlink()
        except OSError:
            pass

        self._emit_event(EventType.FILE_DECRYPTED, f"Decryption Approved and completed for file {original_name}", status="approved")
        
        self.after(0, self._set_loading_state, False, "File successfully decrypted!")
        self.after(0, self.entry_key.delete, 0, "end")
        self.after(0, lambda: self.lbl_selected_file.configure(text="No file selected", text_color="gray"))
        self.selected_file = None
        self.after(0, lambda: messagebox.showinfo("Success", f"File successfully decrypted:\n{restored_path.name}"))
