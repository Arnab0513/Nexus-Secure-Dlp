import cv2
from .base import CameraProvider, CameraCaptureResult

class OpenCVCameraProvider(CameraProvider):
    """Generic OpenCV camera capture. Extendable by Windows/Linux for specific APIs."""
    
    def __init__(self, backend=cv2.CAP_ANY, platform_name="Generic"):
        self.backend = backend
        self.platform_name = platform_name
        
    def list_cameras(self) -> list[dict]:
        """Attempt to blindly probe indices for available cameras."""
        cameras = []
        for i in range(5):
            cap = cv2.VideoCapture(i, self.backend)
            if cap.isOpened():
                cameras.append({
                    "Name": f"Camera {i}",
                    "Position": str(i),
                    "Backend": str(self.backend)
                })
                cap.release()
        return cameras

    def capture(self, output_path: str) -> CameraCaptureResult:
        """Capture from the first available camera."""
        # Find first working camera index
        selected_idx = None
        for i in range(5):
            cap = cv2.VideoCapture(i, self.backend)
            if cap.isOpened():
                selected_idx = i
                break
                
        if selected_idx is None:
            return CameraCaptureResult(
                success=False,
                platform=self.platform_name,
                error="No camera could be opened using OpenCV."
            )
            
        ret, frame = cap.read()
        cap.release()
        
        if not ret:
            return CameraCaptureResult(
                success=False,
                platform=self.platform_name,
                error="Camera opened but failed to read frame."
            )
            
        success = cv2.imwrite(output_path, frame)
        if success:
            return CameraCaptureResult(
                success=True,
                image_path=output_path,
                camera_name=f"Camera Index {selected_idx}",
                camera_id=str(selected_idx),
                platform=self.platform_name,
                is_builtin=True, # Assuming local physical webcam on Windows/Linux
                is_continuity_camera=False
            )
        else:
            return CameraCaptureResult(
                success=False,
                platform=self.platform_name,
                error="Failed to write frame to disk."
            )
