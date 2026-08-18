from __future__ import annotations
import subprocess
from pathlib import Path
from .base import CameraProvider, CameraCaptureResult

class MacOSCameraProvider(CameraProvider):
    """Native macOS camera selection using AVFoundation via Swift."""
    
    def __init__(self):
        # Path to the pre-compiled swift binary
        self._swift_bin = Path(__file__).parent / "macos_camera_bin"
        if not self._swift_bin.exists():
            # Fallback to source if binary is missing
            self._swift_bin = ["swift", str(Path(__file__).parent / "macos_camera.swift")]
        else:
            self._swift_bin = [str(self._swift_bin)]
            
    def list_cameras(self) -> list[dict]:
        """Execute the swift script to list cameras and parse the output."""
        try:
            cmd = self._swift_bin + ["--list"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[CAMERA] Failed to list cameras via AVFoundation. Error: {e.stderr}")
            return []

        cameras = []
        current_cam = {}
        
        for line in result.stdout.splitlines():
            line = line.strip()
            if line == "--------------------------------":
                if current_cam:
                    cameras.append(current_cam)
                    current_cam = {}
                continue
            if line == "Camera" or not line or line == "Available cameras:" or line.startswith("nexus_agent"):
                continue
                
            if ": " in line:
                key, val = line.split(": ", 1)
                current_cam[key] = val
                
        if current_cam:
            cameras.append(current_cam)
            
        return cameras

    def _find_builtin_mac_camera(self) -> dict | None:
        """Find the best camera, preferring the built-in MacBook camera and ignoring iPhone."""
        cameras = self.list_cameras()
        if not cameras:
            return None
            
        # Step 1: Filter out Continuity Cameras
        valid_cameras = []
        for cam in cameras:
            if cam.get("Continuity/iPhone") == "YES":
                continue
            valid_cameras.append(cam)
            
        if not valid_cameras:
            return None
            
        # Step 2: Look for explicitly built-in
        for cam in valid_cameras:
            if cam.get("Built-in") == "YES":
                return cam
                
        # Step 3: Fallback to the first non-continuity camera
        return valid_cameras[0]

    def capture(self, output_path: str) -> CameraCaptureResult:
        """Capture a frame using the native Swift AVFoundation helper."""
        selected = self._find_builtin_mac_camera()
        if not selected:
            return CameraCaptureResult(
                success=False,
                platform="macOS",
                error="Built-in MacBook camera could not be identified."
            )
            
        try:
            cmd = self._swift_bin + ["--capture-builtin", output_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if "SUCCESS" in result.stdout:
                return CameraCaptureResult(
                    success=True,
                    image_path=output_path,
                    camera_name=selected.get("Name", "Unknown MacBook Camera"),
                    camera_id=selected.get("Unique ID", ""),
                    platform="macOS",
                    is_builtin=True,
                    is_continuity_camera=False
                )
            else:
                return CameraCaptureResult(
                    success=False,
                    platform="macOS",
                    error=f"Webcam capture failed: {result.stdout} {result.stderr}"
                )
        except subprocess.CalledProcessError as e:
            return CameraCaptureResult(
                success=False,
                platform="macOS",
                error=f"Webcam capture subprocess failed: {e.stderr}"
            )
