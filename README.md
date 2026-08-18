# NEXUS Secure DLP (Data Loss Prevention)

A comprehensive Endpoint Security Platform designed to prevent unauthorized data access, encrypt files in transit, and monitor endpoints through a Security Operations Center (SOC) server.

## 🏗️ Project Architecture

The project is split into three main components:

### 1. NEXUS Agent (`nexus_agent/`)
A background daemon running continuously on the endpoint (e.g., employee laptop).
- **Auto-Monitoring:** Watches designated folders (Desktop, Documents, Downloads, USB drives) and auto-encrypts sensitive files.
- **Intruder Capture:** Utilizes webcam hardware to capture unauthorized access attempts using OpenCV face detection.
- **Telemetry:** Sends real-time heartbeats and security events (NORMAL, MEDIUM, HIGH) to the SOC server.

### 2. NEXUS Decrypt App (`user_app/`)
A premium Desktop GUI application (built with pywebview and HTML/CSS/JS) for authorized users to decrypt files.
- **Secure File Handling:** Select and decrypt `.ndlp` (NEXUS Data Loss Prevention) packages.
- **Server Authentication:** Communicates securely with the SOC server to validate passwords and obtain decryption keys (`Fernet` AES-256).

### 3. NEXUS SOC Server (`server/`)
A centralized Security Operations Center (SOC) Flask backend to monitor and manage all endpoints.
- **Dashboard:** Real-time web UI showing event telemetry, active endpoints, and threat analytics.
- **Access Management:** Admins can authorize, block, or revoke endpoints.
- **Immutable Logging:** Stores a blockchain-style log of all security events.
- **Key Management:** Generates and distributes decryption keys based on department password verification.
- **Alerts:** Triggers immediate email notifications with webcam attachments for HIGH severity threats.

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Virtual Environment

### 1. Run the Server
Ensure you are using the correct network IP or `localhost` if running locally.
```bash
# From the project root
source .venv/bin/activate
cd server
python server.py
```
> The dashboard will be available at `http://127.0.0.1:5050`. Default Admin Password: `Arnab@2026`

### 2. Run the Endpoint Agent
The agent runs in the background and secures the host machine.
```bash
# From the project root
source .venv/bin/activate
cd nexus_agent
python main.py
```

### 3. Run the Decrypt GUI
The end-user application to decrypt `.ndlp` packages.
```bash
# From the project root
source .venv/bin/activate
cd user_app
python app.py
```

## 🔒 Security Workflow
1. A file is created in a monitored folder. The `nexus_agent` automatically detects it and requests encryption.
2. The `server` generates an AES-256 `Fernet` key based on the file's department signature and returns it.
3. The agent encrypts the file into an `.ndlp` package and drops the original.
4. When a user tries to decrypt it via the `user_app` GUI, they must provide the correct department password.
5. If the password is wrong, access is denied (403), the webcam silently captures an image of the user, and an email alert is sent to the administrator.

## ⚙️ Environment Variables (Server)
To enable full server functionality, set the following environment variables:
- `EMAIL_ENABLED=true`
- `EMAIL_SENDER=your_email@gmail.com`
- `EMAIL_PASSWORD=your_app_password`
- `EMAIL_RECEIVER=recipient_email@gmail.com`
- `SECRET_KEY=your_flask_secret_key`
