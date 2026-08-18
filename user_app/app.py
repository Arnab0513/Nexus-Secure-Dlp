"""
NEXUS Secure File Decrypt — Desktop GUI Application (pywebview).

A premium-looking application using HTML/CSS/JS in a native WebKit window.
"""
from __future__ import annotations

import sys
import threading
import socket
from pathlib import Path
import json

import webview
import yaml

from decryption_core import (
    DecryptionError,
    ServerAuthError,
    ServerConnectionError,
    decrypt_file,
    parse_ndlp,
    NdlpPackage
)

IPC_PORT = 50505
_APP_DIR = Path(__file__).resolve().parent
_CONFIG_PATH = _APP_DIR / "config.yaml"

def _load_server_url() -> str:
    """Load the server URL from config.yaml."""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("server_url", "http://127.0.0.1:5050")
    except Exception:
        return "http://127.0.0.1:5050"


class Api:
    """Python API exposed to the JavaScript frontend."""
    
    def __init__(self, window_manager):
        self.window_manager = window_manager
        self.current_package: NdlpPackage | None = None
        self.current_file_path: Path | None = None
        self.server_url = _load_server_url()
        
    def browse_file(self):
        """Open a file dialog to select a .ndlp file."""
        window = self.window_manager.window
        file_types = ('NEXUS DLP Packages (*.ndlp)', 'All files (*.*)')
        result = window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False, file_types=file_types)
        
        if result:
            file_path = Path(result[0])
            return self._load_file(file_path)
        return None
        
    def _load_file(self, file_path: Path):
        """Parse the package and return info to JS."""
        try:
            self.current_package = parse_ndlp(file_path)
            self.current_file_path = file_path
            
            import os
            size_bytes = os.path.getsize(file_path)
            
            return {
                "filename": self.current_package.source_path.name,
                "size": f"{size_bytes} bytes",
                "department": self.current_package.created_by
            }
        except Exception as e:
            window = self.window_manager.window
            if window:
                window.evaluate_js(f'alert("Invalid Package: {str(e)}")')
            return None

    def decrypt_file(self, token: str):
        """Decrypt the selected file."""
        if not self.current_file_path:
            return {"success": False, "error": "No file selected."}
            
        try:
            out_path = decrypt_file(
                ndlp_path=self.current_file_path,
                auth_token=token,
                server_url=self.server_url,
                auto_open=True,
            )
            return {
                "success": True, 
                "message": f"File decrypted successfully to:\n{out_path.name}"
            }
        except ServerConnectionError as e:
            return {"success": False, "error": "Cannot connect to server."}
        except ServerAuthError:
            return {"success": False, "error": "Invalid auth token or server rejected access."}
        except DecryptionError as e:
            return {"success": False, "error": f"Decryption failed: {e}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {e}"}


class WindowManager:
    def __init__(self):
        self.window = None


def run_ipc_server(api: Api, window_manager: WindowManager):
    """Listens for file paths from other instances."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("127.0.0.1", IPC_PORT))
        server.listen(1)
    except OSError:
        return
        
    while True:
        try:
            conn, _ = server.accept()
            data = conn.recv(4096).decode("utf-8").strip()
            conn.close()
            
            if data and window_manager.window:
                file_path = Path(data)
                if file_path.exists():
                    file_info = api._load_file(file_path)
                    if file_info:
                        js_code = f"window.handleFileSelected({json.dumps(file_info)});"
                        window_manager.window.evaluate_js(js_code)
                        window_manager.window.restore()
        except Exception:
            pass


def main() -> None:
    initial_file = None
    if len(sys.argv) > 1:
        initial_file = Path(sys.argv[1]).resolve()
        
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", IPC_PORT))
            client.sendall(str(initial_file).encode("utf-8"))
            client.close()
            sys.exit(0)
        except ConnectionRefusedError:
            pass

    window_manager = WindowManager()
    api = Api(window_manager)
    
    threading.Thread(target=run_ipc_server, args=(api, window_manager), daemon=True).start()
    
    ui_path = Path(__file__).parent / "ui" / "index.html"
    
    window_manager.window = webview.create_window(
        title='NEXUS Secure Decrypt',
        url=f'file://{ui_path}',
        width=580,
        height=620,
        resizable=False,
        frameless=False,
        background_color='#0A0F1C',
        js_api=api
    )
    
    def on_loaded():
        if initial_file and initial_file.exists():
            file_info = api._load_file(initial_file)
            if file_info:
                js_code = f"window.handleFileSelected({json.dumps(file_info)});"
                window_manager.window.evaluate_js(js_code)
                
    webview.windows[0].events.loaded += on_loaded
    webview.start()

if __name__ == "__main__":
    main()
