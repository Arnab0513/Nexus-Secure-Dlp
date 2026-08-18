#!/bin/bash
# ============================================================
# NEXUS Secure File Decrypt — macOS Launcher
# ============================================================
# Double-click this file to launch the NEXUS Decrypt app.
# No terminal knowledge required.
# ============================================================

cd "$(dirname "$0")"

# Use the project venv if it exists, otherwise system python3
if [ -f "../.venv/bin/python3" ]; then
    PYTHON="../.venv/bin/python3"
elif [ -f "../.venv/bin/python" ]; then
    PYTHON="../.venv/bin/python"
else
    PYTHON="python3"
fi

# Pass any .ndlp file argument (for "Open With" support)
exec "$PYTHON" app.py "$@"
