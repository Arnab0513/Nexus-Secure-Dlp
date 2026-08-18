import argparse
import base64
import getpass
import json
import os
import socket
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import requests
from cryptography.fernet import Fernet

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
CLIENT_DATA = BASE_DIR / "client_data"
CLIENT_DATA.mkdir(exist_ok=True)
CONFIG_FILE = CLIENT_DATA / "client_config.json"
PACKAGE_DB = CLIENT_DATA / "package_registry.json"
INTRUSION_DIR = CLIENT_DATA / "intrusions"
INTRUSION_DIR.mkdir(exist_ok=True)
OWNER_MODEL = CLIENT_DATA / "owner_lbph.yml"
OWNER_LABELS = CLIENT_DATA / "owner_labels.json"
HAAR_FACE = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"

DEFAULT_CONFIG = {
    "server_url": os.environ.get("SERVER_URL", "http://127.0.0.1:5050"),
    "device_name": socket.gethostname(),
    "watch_folder": str(BASE_DIR / "usb_simulated"),
    "file_extensions": [".txt", ".pdf", ".docx", ".xlsx", ".png", ".jpg"],
}


def ensure_json(path: Path, default):
    if not path.exists():
        path.write_text(json.dumps(default, indent=2), encoding="utf-8")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_config():
    return ensure_json(CONFIG_FILE, DEFAULT_CONFIG)


def load_registry():
    return ensure_json(PACKAGE_DB, {})


def save_registry(data):
    save_json(PACKAGE_DB, data)


def server_url():
    return load_config()["server_url"].rstrip("/")


def device_name():
    return load_config()["device_name"]


def log(msg: str):
    print(msg)


def post_json(route: str, payload: dict, timeout: int = 20):
    url = server_url() + route
    return requests.post(url, json=payload, timeout=timeout)


def enroll_with_server():
    cfg = load_config()
    res = post_json("/client/enroll", {"device": cfg["device_name"]})
    res.raise_for_status()
    return res.json()


def send_event(file_name: str, action: str, severity: str | None = None, **kwargs):
    payload = {"device": device_name(), "file": file_name, "action": action}
    if severity:
        payload["severity"] = severity
    payload.update(kwargs)
    try:
        post_json("/client/log-event", payload, timeout=10)
    except Exception as exc:
        log(f"[WARN] could not send event to server: {exc}")


def fernet_from_key(key_str: str) -> Fernet:
    return Fernet(key_str.encode())


def encrypt_file(path: Path):
    path = Path(path)
    if not path.exists() or path.suffix == ".ndlp":
        return
    res = post_json("/client/request-encryption", {"device": device_name(), "file_name": path.name})
    res.raise_for_status()
    data = res.json()
    package_id = data["package_id"]
    file_key = data["file_key"]
    auth_token = data["auth_token"]

    cipher = fernet_from_key(file_key)
    ciphertext = cipher.encrypt(path.read_bytes())
    package = {
        "package_id": package_id,
        "original_name": path.name,
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "created_by": device_name(),
    }
    out_path = path.with_suffix(path.suffix + ".ndlp")
    out_path.write_text(json.dumps(package, indent=2), encoding="utf-8")

    reg = load_registry()
    reg[package_id] = {
        "package_file": str(out_path),
        "original_name": path.name,
        "auth_token": auth_token,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "authorized_devices": [device_name()],
    }
    save_registry(reg)
    send_event(path.name, f"Encrypted into package {package_id}", "NORMAL")
    log(f"[OK] Encrypted {path.name} -> {out_path.name} | package={package_id}")
    return out_path


def detect_and_capture_intruder() -> tuple[str | None, str]:
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    cam.release()
    if not ret:
        return None, "camera-failed"

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    detector = cv2.CascadeClassifier(HAAR_FACE)
    faces = detector.detectMultiScale(gray, 1.3, 5)
    label = "unknown"

    if len(faces) and hasattr(cv2, "face") and OWNER_MODEL.exists() and OWNER_LABELS.exists():
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.read(str(OWNER_MODEL))
        labels = ensure_json(OWNER_LABELS, {})
        x, y, w, h = faces[0]
        face_roi = gray[y:y+h, x:x+w]
        try:
            predicted_id, confidence = recognizer.predict(face_roi)
            if confidence < 65:
                label = labels.get(str(predicted_id), "recognized-owner")
            else:
                label = "unknown"
        except Exception:
            label = "unknown"
    elif len(faces):
        label = "face-detected"

    filename = INTRUSION_DIR / f"intruder_{time.strftime('%Y%m%d_%H%M%S')}.jpg"
    cv2.imwrite(str(filename), frame)
    return str(filename), label


def authorize_other_device(package_id: str, target_device: str):
    manager_password = getpass.getpass("Server manager password: ")
    res = post_json(
        "/client/register-package-device",
        {"package_id": package_id, "target_device": target_device, "manager_password": manager_password},
    )
    res.raise_for_status()
    reg = load_registry()
    if package_id in reg:
        reg[package_id].setdefault("authorized_devices", [])
        if target_device not in reg[package_id]["authorized_devices"]:
            reg[package_id]["authorized_devices"].append(target_device)
            save_registry(reg)
    log(f"[OK] package {package_id} now authorized for {target_device}")


def decrypt_package(package_path: Path, auth_token: str | None = None, output_dir: str | None = None):
    package_path = Path(package_path)
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package_id = package["package_id"]
    file_name = package["original_name"]
    reg = load_registry()
    token = auth_token or reg.get(package_id, {}).get("auth_token")
    if not token:
        token = getpass.getpass("Enter server-issued auth token: ")

    intrusion_path = None
    face_label = "not-captured"
    payload = {
        "device": device_name(),
        "package_id": package_id,
        "auth_token": token,
        "file_name": file_name,
        "face_label": face_label,
    }

    try:
        res = post_json("/client/request-decryption", payload)
        res.raise_for_status()
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 403:
            try:
                import sys
                import base64
                from pathlib import Path
                agent_dir = str(Path(__file__).resolve().parent.parent / "nexus_agent")
                if agent_dir not in sys.path:
                    sys.path.insert(0, agent_dir)
                    
                from core.intruder_capture import IntruderCapture  # type: ignore
                from config import NexusConfig  # type: ignore
                intruder = IntruderCapture(NexusConfig.load(), None)
                image_path, _ = intruder.capture()
                b64_img = None
                if image_path:
                    with open(image_path, "rb") as f:
                        b64_img = base64.b64encode(f.read()).decode('utf-8')
                
                send_event(file_name, f"Unauthorized/failed decryption attempt for package {package_id}", "HIGH", intrusion_image_b64=b64_img)
            except Exception as e:
                send_event(file_name, f"Unauthorized/failed decryption attempt for package {package_id}", "HIGH")
        else:
            send_event(file_name, f"Unauthorized/failed decryption attempt for package {package_id}", "NORMAL")
        log(f"[DENIED] {exc}")
        return None

    data = res.json()
    file_key = data["file_key"]
    cipher = fernet_from_key(file_key)
    plaintext = cipher.decrypt(base64.b64decode(package["ciphertext_b64"]))

    out_dir = Path(output_dir) if output_dir else package_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / file_name
    out_path.write_bytes(plaintext)
    send_event(file_name, f"Successfully decrypted package {package_id}", "MEDIUM")
    log(f"[OK] Decrypted -> {out_path}")
    return out_path


class USBFolderHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        cfg = load_config()
        if path.suffix.lower() in [x.lower() for x in cfg.get("file_extensions", [])]:
            time.sleep(0.8)
            try:
                encrypt_file(path)
            except Exception as exc:
                log(f"[ERROR] monitor encrypt failed: {exc}")
                send_event(path.name, f"Encryption failed: {exc}", "HIGH")


def monitor_folder():
    cfg = load_config()
    watch_path = Path(cfg["watch_folder"])
    watch_path.mkdir(parents=True, exist_ok=True)
    if not WATCHDOG_AVAILABLE:
        raise RuntimeError("watchdog is not installed. pip install watchdog")
    observer = Observer()
    observer.schedule(USBFolderHandler(), str(watch_path), recursive=False)
    observer.start()
    log(f"[MONITOR] watching {watch_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def train_owner_model(dataset_dir: Path, label: str = "owner"):
    if not hasattr(cv2, "face"):
        raise RuntimeError("opencv-contrib-python is required for face recognition training")
    detector = cv2.CascadeClassifier(HAAR_FACE)
    images = []
    labels = []
    label_map = {0: label}
    for img_path in Path(dataset_dir).glob("*.jpg"):
        img = cv2.imread(str(img_path), cv2.IMREAD_GRAYSCALE)
        if img is None:
            continue
        faces = detector.detectMultiScale(img, 1.3, 5)
        for (x, y, w, h) in faces[:1]:
            images.append(img[y:y+h, x:x+w])
            labels.append(0)
    if not images:
        raise RuntimeError("No usable face samples found")
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.train(images, np.array(labels, dtype='int32'))
    recognizer.save(str(OWNER_MODEL))
    save_json(OWNER_LABELS, {"0": label})
    log(f"[OK] owner face model trained with {len(images)} samples")


def init_config(server_ip: str):
    cfg = load_config()
    cfg["server_url"] = f"http://{server_ip}:5050"
    cfg["device_name"] = socket.gethostname()
    save_json(CONFIG_FILE, cfg)
    Path(cfg["watch_folder"]).mkdir(parents=True, exist_ok=True)
    log(f"[OK] Config saved -> {CONFIG_FILE}")
    log(f"[INFO] Share this device name with server manager: {cfg['device_name']}")


def main():
    parser = argparse.ArgumentParser(description="NEXUS client agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init_p = sub.add_parser("init")
    init_p.add_argument("server_ip", help="Hotspot IP of the server machine")

    sub.add_parser("enroll")

    enc = sub.add_parser("encrypt")
    enc.add_argument("file")

    dec = sub.add_parser("decrypt")
    dec.add_argument("package_file")
    dec.add_argument("--token", default=None)
    dec.add_argument("--out", default=None)

    auth = sub.add_parser("authorize-device")
    auth.add_argument("package_id")
    auth.add_argument("target_device")

    sub.add_parser("monitor")

    train = sub.add_parser("train-face")
    train.add_argument("dataset_dir")
    train.add_argument("--label", default="owner")

    args = parser.parse_args()

    if args.cmd == "init":
        init_config(args.server_ip)
    elif args.cmd == "enroll":
        print(enroll_with_server())
    elif args.cmd == "encrypt":
        encrypt_file(Path(args.file))
    elif args.cmd == "decrypt":
        decrypt_package(Path(args.package_file), args.token, args.out)
    elif args.cmd == "authorize-device":
        authorize_other_device(args.package_id, args.target_device)
    elif args.cmd == "monitor":
        monitor_folder()
    elif args.cmd == "train-face":
        train_owner_model(Path(args.dataset_dir), args.label)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)
