#!/usr/bin/env python3
"""
Build Windows Installer for Yahoo-Discord Bridge

This script builds a complete Windows installer that:
1. Creates standalone .exe using PyInstaller
2. Bundles everything into a single setup.exe using Inno Setup
3. The resulting installer does EVERYTHING automatically for the user

Can be run on:
- Windows: Direct build
- Linux: Cross-compile using Wine (requires wine + python installed in wine)

Usage:
    python build_windows.py           # Build just the exe
    python build_windows.py --full    # Build exe + installer
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
INSTALLER_DIR = PROJECT_ROOT / "installer"


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def run(cmd, **kwargs):
    """Run a command and return success status"""
    print(f"  Running: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, **kwargs)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error: {e}")
        return False


def clean():
    """Clean previous build artifacts"""
    print_header("Cleaning previous builds")
    for folder in [DIST_DIR, BUILD_DIR]:
        if folder.exists():
            shutil.rmtree(folder)
            print(f"  Removed {folder}")
    print("  Done")


def install_dependencies():
    """Install build dependencies"""
    print_header("Installing dependencies")
    run(f"{sys.executable} -m pip install --upgrade pyinstaller")
    run(f"{sys.executable} -m pip install -r requirements.txt")


def build_exe():
    """Build standalone exe using PyInstaller"""
    print_header("Building Windows executable")

    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        "--name", "YahooDiscordBridge",
        "--add-data", f"ymsg{os.pathsep}ymsg",
        "--add-data", f"discord_client{os.pathsep}discord_client",
        "--add-data", f"mapping{os.pathsep}mapping",
        "--hidden-import", "discord",
        "--hidden-import", "aiohttp",
        "--hidden-import", "asyncio",
    ]

    # Add icon if it exists
    icon_path = INSTALLER_DIR / "yahoo.ico"
    if icon_path.exists():
        cmd.extend(["--icon", str(icon_path)])

    # Main script
    cmd.append("app.py")

    # Run PyInstaller
    if not run(" ".join(cmd)):
        print("\n  ERROR: PyInstaller build failed!")
        return False

    # Check output
    exe_path = DIST_DIR / "YahooDiscordBridge.exe"
    if not exe_path.exists():
        # Try without .exe (Linux build)
        exe_path = DIST_DIR / "YahooDiscordBridge"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n  SUCCESS: Built {exe_path}")
        print(f"  Size: {size_mb:.1f} MB")
        return True
    else:
        print("\n  ERROR: Output executable not found!")
        return False


def build_installer():
    """Build Windows installer using Inno Setup"""
    print_header("Building Windows installer")

    # Check for Inno Setup
    iscc_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        "/usr/bin/iscc",  # Linux with Inno Setup via Wine
        "iscc",  # In PATH
    ]

    iscc = None
    for path in iscc_paths:
        if os.path.exists(path) or shutil.which(path):
            iscc = path
            break

    if not iscc:
        # Try Wine on Linux
        if platform.system() == "Linux":
            wine_iscc = os.path.expanduser("~/.wine/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe")
            if os.path.exists(wine_iscc):
                iscc = f'wine "{wine_iscc}"'

    if not iscc:
        print("  WARNING: Inno Setup not found!")
        print("  - Windows: Install from https://jrsoftware.org/isinfo.php")
        print("  - Linux: Install via Wine")
        print("\n  Skipping installer build. You can still use the standalone .exe")
        return False

    # Create output directory
    output_dir = INSTALLER_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    # Build installer
    iss_file = INSTALLER_DIR / "setup_allinone.iss"
    if not iss_file.exists():
        print(f"  ERROR: {iss_file} not found!")
        return False

    if not run(f'{iscc} "{iss_file}"'):
        print("\n  ERROR: Installer build failed!")
        return False

    # Check output
    installer = output_dir / "YahooDiscordBridge_Setup_v1.0.0.exe"
    if installer.exists():
        size_mb = installer.stat().st_size / (1024 * 1024)
        print(f"\n  SUCCESS: Built {installer}")
        print(f"  Size: {size_mb:.1f} MB")
        return True
    else:
        print("\n  WARNING: Installer file not found at expected location")
        return False


def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║       Yahoo-Discord Bridge - Windows Build Script        ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    os.chdir(PROJECT_ROOT)

    # Parse arguments
    full_build = "--full" in sys.argv

    # Clean
    clean()

    # Install dependencies
    install_dependencies()

    # Build exe
    if not build_exe():
        print("\n\nBuild failed!")
        sys.exit(1)

    # Build installer if requested
    if full_build:
        build_installer()

    # Summary
    print_header("Build Complete!")
    print("  Output files:")
    print(f"  - {DIST_DIR}/YahooDiscordBridge.exe (standalone)")
    if full_build:
        print(f"  - {INSTALLER_DIR}/output/YahooDiscordBridge_Setup_v1.0.0.exe (installer)")

    print("""
  Next steps:
  1. Copy the .exe or installer to a Windows machine
  2. Run it and enter your Discord token
  3. Open Yahoo Messenger and sign in
  4. Your Discord friends appear in your buddy list!
    """)


if __name__ == "__main__":
    main()
