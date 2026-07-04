import os
import time
import subprocess
from .pcap_parser import PCAPParser
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from config import settings

class DynamicEngine:
    def __init__(self, apk_path: str, package_name: str, duration: int = 30):
        self.apk_path = apk_path
        self.package_name = package_name
        self.duration = duration
        self.pcap_device_path = "/sdcard/capture.pcap"
        self.pcap_local_path = os.path.join(os.path.dirname(apk_path), "capture.pcap")
        
        # Determine ADB path. If settings.ADB_PATH is the default unix path on Windows, just use 'adb'
        self.adb_cmd = settings.ADB_PATH if settings.ADB_PATH and os.path.exists(settings.ADB_PATH) else "adb"

    def _run_adb(self, args: list) -> tuple:
        try:
            cmd = [self.adb_cmd] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0, result.stdout, result.stderr
        except FileNotFoundError:
            return False, "", f"{self.adb_cmd} not installed or not in PATH"
        except subprocess.TimeoutExpired:
            return False, "", "ADB command timed out"
        except Exception as e:
            return False, "", str(e)

    def check_environment(self) -> bool:
        success, stdout, stderr = self._run_adb(["devices"])
        if not success:
            return False
            
        lines = stdout.strip().split("\n")
        devices = [line for line in lines[1:] if "device" in line and "offline" not in line]
        return len(devices) > 0

    def run_analysis(self) -> dict:
        if not self.check_environment():
            return {"error": "No Android device/emulator connected or ADB is not available."}

        print(f"  [*] Starting dynamic analysis for {self.package_name} ({self.duration}s)...")
        results = {}

        # 1. Install APK
        print("  [*] Installing APK on device...")
        success, stdout, stderr = self._run_adb(["install", "-r", self.apk_path])
        if not success:
            return {"error": f"Failed to install APK: {stderr}"}

        # 2. Start tcpdump (Requires root)
        print("  [*] Starting packet capture (tcpdump)...")
        # Remove old pcap
        self._run_adb(["shell", "rm", "-f", self.pcap_device_path])
        
        # Start tcpdump in background. -s 0 captures full packets, -w writes to file
        # This will fail silently if the device is not rooted or doesn't have tcpdump, 
        # which is why we wrap it gracefully.
        tcpdump_cmd = ["shell", f"su -c 'tcpdump -i any -s 0 -w {self.pcap_device_path} >/dev/null 2>&1 &'"]
        self._run_adb(tcpdump_cmd)
        
        # Give tcpdump a moment to start
        time.sleep(2)

        # 3. Launch App using Monkey
        print("  [*] Launching app and simulating user interaction...")
        self._run_adb(["shell", "monkey", "-p", self.package_name, "-v", "500"])

        # 4. Wait to gather traffic
        print(f"  [*] Waiting {self.duration} seconds for C2 beacons...")
        time.sleep(self.duration)

        # 5. Stop tcpdump
        print("  [*] Stopping packet capture...")
        self._run_adb(["shell", "su", "-c", "killall tcpdump"])
        time.sleep(2)

        # 6. Pull PCAP
        print("  [*] Pulling PCAP file...")
        self._run_adb(["pull", self.pcap_device_path, self.pcap_local_path])

        # 7. Uninstall APK
        print("  [*] Uninstalling APK...")
        self._run_adb(["uninstall", self.package_name])

        # 8. Parse PCAP
        if os.path.exists(self.pcap_local_path):
            print("  [*] Parsing network traffic...")
            parser = PCAPParser(self.pcap_local_path)
            pcap_data = parser.parse()
            results['network_traffic'] = pcap_data
        else:
            results['network_traffic'] = {"error": "PCAP file was not generated (device might not be rooted)."}

        results['status'] = "completed"
        return results
