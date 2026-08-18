import sys
import os

# Ensure nexus_agent is in path if run directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from nexus_agent.services.camera_provider import get_camera_provider

def list_cameras():
    print("Initializing Camera Diagnostics...")
    provider = get_camera_provider()
    
    # We can infer OS from the provider class name or fallback
    print(f"\n[CAMERA] Operating System: {provider.__class__.__name__.replace('CameraProvider', '')}")
    print("[CAMERA] Detecting cameras...\n")
    
    cameras = provider.list_cameras()
    if not cameras:
        print("[CAMERA] No cameras detected.")
        return
        
    for i, cam in enumerate(cameras, start=1):
        print(f"{i}.")
        print(f"Name: {cam.get('Name', 'Unknown')}")
        print(f"ID: {cam.get('Unique ID', cam.get('ID', 'Unknown'))}")
        print(f"Backend: {cam.get('Backend', 'AVFoundation' if 'macOS' in str(provider.__class__) else 'Unknown')}")
        print(f"Built-in: {cam.get('Built-in', 'Unknown')}")
        print(f"Continuity Camera: {cam.get('Continuity/iPhone', 'Unknown')}")
        print("-" * 30)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        list_cameras()
    else:
        print("Usage: python -m nexus_agent.camera --list")
