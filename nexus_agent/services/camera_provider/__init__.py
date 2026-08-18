import platform
from .base import CameraProvider, CameraCaptureResult

def get_camera_provider() -> CameraProvider:
    """
    Factory function to return the correct camera provider for the current OS.
    Uses delayed imports so missing dependencies (e.g., Swift on Windows) 
    do not crash the process.
    """
    system = platform.system()
    
    if system == "Darwin":
        try:
            from .macos_provider import MacOSCameraProvider
            return MacOSCameraProvider()
        except Exception as e:
            print(f"[CAMERA INIT] Failed to load macOS provider: {e}. Falling back to OpenCV.")
            from .fallback_provider import OpenCVCameraProvider
            import cv2
            return OpenCVCameraProvider(backend=cv2.CAP_ANY, platform_name="macOS (Fallback)")
            
    elif system == "Windows":
        try:
            from .windows_provider import WindowsCameraProvider
            return WindowsCameraProvider()
        except Exception as e:
            print(f"[CAMERA INIT] Failed to load Windows provider: {e}. Falling back to OpenCV.")
            from .fallback_provider import OpenCVCameraProvider
            import cv2
            return OpenCVCameraProvider(backend=cv2.CAP_ANY, platform_name="Windows (Fallback)")
            
    elif system == "Linux":
        try:
            from .linux_provider import LinuxCameraProvider
            return LinuxCameraProvider()
        except Exception as e:
            print(f"[CAMERA INIT] Failed to load Linux provider: {e}. Falling back to OpenCV.")
            from .fallback_provider import OpenCVCameraProvider
            import cv2
            return OpenCVCameraProvider(backend=cv2.CAP_ANY, platform_name="Linux (Fallback)")
            
    else:
        # Fallback for unknown OS
        from .fallback_provider import OpenCVCameraProvider
        import cv2
        return OpenCVCameraProvider(backend=cv2.CAP_ANY, platform_name=f"Unknown ({system})")
