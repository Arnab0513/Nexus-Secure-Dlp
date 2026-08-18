import cv2
from .fallback_provider import OpenCVCameraProvider

class WindowsCameraProvider(OpenCVCameraProvider):
    """Windows-specific camera provider using DirectShow or Media Foundation."""
    
    def __init__(self):
        # Prefer DirectShow on Windows for speed, fallback to MSMF
        # We can just use CAP_DSHOW safely since it's Windows
        super().__init__(backend=cv2.CAP_DSHOW, platform_name="Windows")
