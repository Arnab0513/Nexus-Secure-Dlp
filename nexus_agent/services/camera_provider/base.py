from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class CameraCaptureResult:
    """Standardized result for camera capture across all platforms."""
    success: bool
    image_path: str = ""
    camera_name: str = ""
    camera_id: str = ""
    platform: str = ""
    error: str = ""
    is_builtin: bool = False
    is_continuity_camera: bool = False


class CameraProvider(ABC):
    """Abstract base class for platform-specific camera selection and capture."""
    
    @abstractmethod
    def capture(self, output_path: str) -> CameraCaptureResult:
        """
        Capture a frame from the appropriate physical camera and save it to output_path.
        
        Args:
            output_path: Path where the JPEG image should be saved.
            
        Returns:
            CameraCaptureResult containing success status and metadata.
        """
        pass
        
    @abstractmethod
    def list_cameras(self) -> list[dict]:
        """
        Return a list of detected cameras and their metadata for diagnostic purposes.
        """
        pass
