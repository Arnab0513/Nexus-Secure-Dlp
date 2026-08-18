import cv2
from .fallback_provider import OpenCVCameraProvider

class LinuxCameraProvider(OpenCVCameraProvider):
    """Linux-specific camera provider using V4L2."""
    
    def __init__(self):
        # Prefer V4L2 on Linux
        super().__init__(backend=cv2.CAP_V4L2, platform_name="Linux")
