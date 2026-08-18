#!/usr/bin/env python3
"""
NEXUS Secure File Decrypt — OS File Association Setup Helper
Associates .ndlp files with NEXUS Decrypt on Windows and macOS.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

def setup_windows():
    print("Setting up Windows file association for .ndlp...")
    try:
        import winreg
    except ImportError:
        print("Error: winreg module not found. Are you on Windows?")
        return False

    app_path = Path(__file__).resolve().parent / "app.py"
    python_exe = sys.executable

    if python_exe.endswith("python.exe"):
        python_exe = python_exe.replace("python.exe", "pythonw.exe")

    # Command to run when double clicking an .ndlp file
    open_command = f'"{python_exe}" "{app_path}" "%1"'

    try:
        # Create extension key
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.ndlp") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "nexus.ndlp")

        # Create class key
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\nexus.ndlp") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "NEXUS Encrypted File")

        # Create command key
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\nexus.ndlp\shell\open\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, open_command)

        # Notify Windows Explorer of the change (optional but good practice)
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        except Exception:
            pass
            
        print("✅ Windows association complete!")
        print(f"Associated with: {open_command}")
        return True
    except Exception as e:
        print(f"❌ Failed to set Windows association: {e}")
        return False

def setup_macos():
    print("Setting up macOS file association for .ndlp...")
    
    app_dir = Path(__file__).resolve().parent
    command_script = app_dir / "NEXUS Decrypt.command"
    
    applescript = f"""
on open droppedItems
    set posixArgs to ""
    repeat with theItem in droppedItems
        set posixArgs to posixArgs & " " & quoted form of POSIX path of theItem
    end repeat
    do shell script "cd '{app_dir}' && './NEXUS Decrypt.command'" & posixArgs & " > /dev/null 2>&1 &"
end open

on run
    do shell script "cd '{app_dir}' && './NEXUS Decrypt.command' > /dev/null 2>&1 &"
end run
"""

    applescript_path = app_dir / "launcher.applescript"
    output_app = app_dir / "NEXUS Decrypt.app"

    # Write temporary AppleScript
    with open(applescript_path, "w") as f:
        f.write(applescript)

    try:
        print("Compiling AppleScript droplet...")
        subprocess.run(["osacompile", "-o", str(output_app), str(applescript_path)], check=True)
        
        # Modify Info.plist to register .ndlp extension
        plist_path = output_app / "Contents" / "Info.plist"
        
        plist_addition = """
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeExtensions</key>
            <array>
                <string>ndlp</string>
            </array>
            <key>CFBundleTypeName</key>
            <string>NEXUS Encrypted File</string>
            <key>CFBundleTypeRole</key>
            <string>Viewer</string>
            <key>LSHandlerRank</key>
            <string>Owner</string>
        </dict>
    </array>
"""
        
        with open(plist_path, "r") as f:
            content = f.read()
            
        if "<key>CFBundleDocumentTypes</key>" not in content:
            content = content.replace("</dict>\n</plist>", f"{plist_addition}</dict>\n</plist>")
            with open(plist_path, "w") as f:
                f.write(content)

        print(f"✅ macOS association wrapper created: {output_app}")
        print("\\n=== MANUAL STEP REQUIRED ===")
        print("1. Right-click any .ndlp file")
        print("2. Click 'Get Info'")
        print("3. Under 'Open with', select 'NEXUS Decrypt.app'")
        print("4. Click 'Change All...'")
        return True
    except Exception as e:
        print(f"❌ Failed to compile macOS app: {e}")
        return False
    finally:
        if applescript_path.exists():
            os.remove(applescript_path)

def main():
    system = platform.system()
    if system == "Windows":
        setup_windows()
    elif system == "Darwin":
        setup_macos()
    else:
        print(f"Unsupported OS for automated file association: {system}")
        print("You may need to configure your file manager manually.")

if __name__ == "__main__":
    main()
