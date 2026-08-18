"""
NEXUS Endpoint Agent — Intruder Capture.

Captures webcam evidence when authentication fails:
  1. Opens the default camera.
  2. Reads a frame.
  3. Detects faces using Haar cascades.
  4. Optionally recognizes faces with LBPH (if a trained model exists).
  5. Saves the image to captures/ directory.
  6. Returns the image path and face label for server reporting.

Gracefully degrades if no camera is available.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import TYPE_CHECKING

from config import agent_base_dir
from core.models import EventType, SecurityEvent, Severity
from utils.logging_config import get_logger
from utils.platform_info import get_hostname, get_local_ip, get_username

if TYPE_CHECKING:
    from config import NexusConfig
    from services.event_sender import EventSender

logger = get_logger(__name__)

_CAPTURES_DIR = agent_base_dir() / "captures"


class IntruderCapture:
    """
    Webcam-based evidence capture for failed authentication attempts.

    Designed to be called by the EncryptionEngine or CLI when a decryption
    request is denied.  The captured image is stored locally and can be
    base64-encoded for transmission to the server.
    """

    def __init__(
        self,
        config: NexusConfig,
        event_sender: EventSender | None = None,
    ) -> None:
        self._enabled = config.intruder_capture.enabled
        self._sender = event_sender
        self._device = config.device.resolved_name()
        self._captures_dir = _CAPTURES_DIR
        self._captures_dir.mkdir(parents=True, exist_ok=True)

        # Lazy-load OpenCV modules
        self._cv2 = None
        self._haar_path: str = ""
        self._owner_model_path = agent_base_dir() / "data" / "owner_lbph.yml"
        self._owner_labels_path = agent_base_dir() / "data" / "owner_labels.json"

        logger.info("IntruderCapture initialized (enabled=%s)", self._enabled)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(self) -> tuple[str | None, str]:
        """
        Capture a webcam image and detect/recognize faces.

        Returns
        -------
        tuple[str | None, str]
            (image_path, face_label).
            image_path is None if capture failed.
            face_label is one of: 'recognized-owner', 'face-detected',
            'unknown', 'no-face', 'camera-failed', 'disabled'.
        """
        if not self._enabled:
            logger.info("Intruder capture disabled by configuration")
            return None, "disabled"

        cv2 = self._get_cv2()
        if cv2 is None:
            logger.warning("OpenCV not available — cannot capture")
            return None, "opencv-unavailable"

        # --- Open camera ---
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            logger.warning("Could not open webcam")
            cam.release()
            return None, "camera-failed"

        # Allow camera to warm up
        time.sleep(0.3)
        ret, frame = cam.read()
        cam.release()

        if not ret or frame is None:
            logger.warning("Failed to read frame from webcam")
            return None, "camera-failed"

        # --- Detect faces ---
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        haar_path = self._get_haar_path(cv2)
        detector = cv2.CascadeClassifier(haar_path)
        faces = detector.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)

        face_label = "no-face"
        if len(faces) > 0:
            face_label = self._recognize_face(cv2, gray, faces)

        # --- Save image ---
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"intruder_{self._device}_{timestamp}.jpg"
        image_path = self._captures_dir / filename
        cv2.imwrite(str(image_path), frame)
        logger.info("Captured intruder image: %s (face=%s)", image_path.name, face_label)

        # --- Emit event ---
        if self._sender:
            self._sender.send(SecurityEvent(
                event_type=EventType.INTRUDER_IMAGE_CAPTURED,
                severity=Severity.HIGH,
                action=f"Intruder image captured: face={face_label}",
                device_name=self._device,
                computer_name=get_hostname(),
                username=get_username(),
                ip_address=get_local_ip(),
                captured_image_path=str(image_path),
                status="captured",
                remarks=f"face_label={face_label}",
            ))

        return str(image_path), face_label

    @staticmethod
    def encode_image_b64(image_path: str) -> str | None:
        """
        Read an image file and return its base64-encoded string.

        Used for sending evidence to the server's intrusion endpoint.
        """
        path = Path(image_path)
        if not path.exists():
            return None
        try:
            return base64.b64encode(path.read_bytes()).decode()
        except Exception as exc:
            logger.error("Failed to encode image %s: %s", image_path, exc)
            return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_cv2(self):
        """Lazy-load OpenCV to avoid import errors on systems without it."""
        if self._cv2 is not None:
            return self._cv2
        try:
            import cv2
            self._cv2 = cv2
            return cv2
        except ImportError:
            logger.warning("opencv-python is not installed")
            return None

    def _get_haar_path(self, cv2) -> str:
        """Return the path to the Haar cascade for face detection."""
        if not self._haar_path:
            self._haar_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        return self._haar_path

    def _recognize_face(self, cv2, gray_frame, faces) -> str:
        """
        Attempt face recognition using LBPH if a trained model exists.

        Falls back to 'face-detected' if no model is available.
        """
        if not hasattr(cv2, "face"):
            return "face-detected"
        if not self._owner_model_path.exists() or not self._owner_labels_path.exists():
            return "face-detected"

        try:
            import json
            recognizer = cv2.face.LBPHFaceRecognizer_create()
            recognizer.read(str(self._owner_model_path))
            labels = json.loads(self._owner_labels_path.read_text(encoding="utf-8"))

            x, y, w, h = faces[0]
            face_roi = gray_frame[y:y + h, x:x + w]
            predicted_id, confidence = recognizer.predict(face_roi)

            if confidence < 65:
                return labels.get(str(predicted_id), "recognized-owner")
            else:
                return "unknown"
        except Exception as exc:
            logger.warning("Face recognition failed: %s", exc)
            return "face-detected"
