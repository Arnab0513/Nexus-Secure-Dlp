#!/usr/bin/env python3
"""
NEXUS Endpoint Agent — Decryptor UI Launcher.

Initializes the core NEXUS components and launches the 
End User Secure File Decryption application.
"""

import sys
from pathlib import Path

from config import load_config
from core.encryption_engine import EncryptionEngine
from database.local_store import LocalStore
from gui.decrypt_app import DecryptApp
from services.event_sender import EventSender
from services.server_client import ServerClient
from utils.logging_config import setup_logging

def main():
    agent_base_dir = Path(__file__).resolve().parent
    
    # 1. Setup Logging
    setup_logging(str(agent_base_dir))
    
    # 2. Load Config
    config_path = agent_base_dir / "config.yaml"
    config = load_config(str(config_path))
    
    # 3. Initialize DB
    db_path = agent_base_dir / "data" / "nexus_local.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = LocalStore(str(db_path))
    
    # 4. Initialize Core Services
    client = ServerClient(config, store)
    
    sender = EventSender(
        config=config,
        server_client=client,
        local_store=store,
    )
    
    engine = EncryptionEngine(
        config=config,
        server_client=client,
        local_store=store,
        event_sender=sender,
    )
    
    # Start the event sender thread so queued events go out
    sender.start()
    
    # 5. Launch GUI
    try:
        app = DecryptApp(
            config=config,
            encryption_engine=engine,
            event_sender=sender
        )
        app.mainloop()
    finally:
        # Graceful shutdown of services
        sender.stop()

if __name__ == "__main__":
    main()
