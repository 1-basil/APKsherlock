"""
Controls the Android emulator lifecycle for dynamic APK analysis:
boot with traffic capture enabled, install the sample, launch it,
let it run, then shut down and hand back the pcap.

Prerequisites (one-time, see README.md):
  - Android SDK installed, with `emulator` and `adb` on your PATH
  - An AVD already created, e.g. named "dynamic-analysis"
"""

import subprocess
import time
import os
from androguard.misc import AnalyzeAPK

# Hardcoded absolute paths — avoids depending on PATH being set correctly
# in whatever terminal/process launches this script (a common source of
# "file not found" errors, since PATH set with `set` in one cmd window
# doesn't carry over to other windows or to processes started differently).
ANDROID_HOME = r"C:\Android"
ADB = os.path.join(ANDROID_HOME, "platform-tools", "adb.exe")
EMULATOR = os.path.join(ANDROID_HOME, "emulator", "emulator.exe")


def get_package_name(apk_path):
    a, _, _ = AnalyzeAPK(apk_path)
    return a.get_package()


def start_emulator(avd_name, pcap_output_path, boot_timeout=90):
    """Boots the emulator with all guest traffic captured to pcap_output_path."""
    proc = subprocess.Popen(
        [
            EMULATOR,
            "-avd", avd_name,
            "-no-snapshot",
            "-tcpdump", pcap_output_path,
            "-no-audio",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print("[*] Waiting for emulator to boot...")
    subprocess.run([ADB, "wait-for-device"], timeout=boot_timeout)

    # Poll until Android has fully finished booting, not just adb-visible
    waited = 0
    while waited < boot_timeout:
        result = subprocess.run(
            [ADB, "shell", "getprop", "sys.boot_completed"],
            capture_output=True, text=True,
        )
        if result.stdout.strip() == "1":
            print("[*] Emulator booted.")
            return proc
        time.sleep(2)
        waited += 2

    raise TimeoutError("Emulator did not finish booting in time")


def install_apk(apk_path):
    print(f"[*] Installing {apk_path}...")
    result = subprocess.run(
        [ADB, "install", "-r", apk_path],
        capture_output=True, text=True,
    )
    if "Success" not in result.stdout:
        raise RuntimeError(f"APK install failed: {result.stdout} {result.stderr}")


def launch_app(package_name):
    print(f"[*] Launching {package_name}...")
    subprocess.run(
        [
            ADB, "shell", "monkey",
            "-p", package_name,
            "-c", "android.intent.category.LAUNCHER",
            "1",
        ],
        capture_output=True,
    )


def simulate_interaction(taps=5, delay=2):
    """Fires a handful of random taps so the app isn't just sitting idle
    on its splash screen — gives it a better chance to trigger network
    calls that only fire after user interaction."""
    for _ in range(taps):
        subprocess.run(
            [ADB, "shell", "input", "tap", "500", "800"],
            capture_output=True,
        )
        time.sleep(delay)


def stop_emulator(proc):
    print("[*] Stopping emulator...")
    subprocess.run([ADB, "emu", "kill"], capture_output=True)
    proc.wait(timeout=30)