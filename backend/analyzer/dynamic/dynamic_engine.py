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

    def _adb_shell_sync(self, cmd: str) -> tuple:
        """Run a synchronous ADB shell command and return stdout/stderr."""
        return self._run_adb(["shell", cmd])

    def _extract_dynamic_metadata(self) -> dict:
        """Extract metadata (version, permissions) dynamically from the OS after install"""
        success, stdout, stderr = self._adb_shell_sync(f"dumpsys package {self.package_name}")
        if not success:
            return {}

        metadata = {
            "package_name": self.package_name,
            "version_name": "Unknown",
            "version_code": "Unknown",
            "requested_permissions": []
        }

        in_requested_permissions = False
        
        for line in stdout.splitlines():
            line_str = line.strip()
            
            if line_str.startswith("versionName="):
                metadata["version_name"] = line_str.split("=", 1)[1]
            elif line_str.startswith("versionCode="):
                metadata["version_code"] = line_str.split(" ")[0].split("=")[1]
                
            # Permissions parsing
            if line_str == "requested permissions:":
                in_requested_permissions = True
                continue
            elif in_requested_permissions and line_str == "install permissions:":
                in_requested_permissions = False
                
            if in_requested_permissions and line_str.startswith("android.permission."):
                perm = line_str.split(":")[0].strip()
                metadata["requested_permissions"].append(perm)

        return metadata

    def run_analysis(self) -> dict:
        print("USING NEW DYNAMIC ENGINE")
        if not self.check_environment():
            return {"error": "No Android device/emulator connected or ADB is not available."}

        print(f"  [*] Starting dynamic analysis for {self.package_name} ({self.duration}s)...")
        results = {}

        # 1. Capture packages before install if package name is unknown
        pre_install_packages = set()
        if self.package_name == 'unknown':
            _, pm_out, _ = self._adb_shell_sync("pm list packages")
            pre_install_packages = set(pm_out.splitlines())

        # 2. Install APK
        print("  [*] Installing APK on device...")
        success, stdout, stderr = self._run_adb(["install", "-r", self.apk_path])
        if not success:
            return {"error": f"Failed to install APK: {stderr}"}
            
        # 3. Capture packages after install and diff to find the real package name
        if self.package_name == 'unknown':
            _, pm_out, _ = self._adb_shell_sync("pm list packages")
            post_install_packages = set(pm_out.splitlines())
            diff = post_install_packages - pre_install_packages
            if diff:
                # Get the first newly installed package, removing 'package:' prefix
                new_pkg = list(diff)[0].replace("package:", "").strip()
                print(f"  [+] Dynamically resolved package name: {new_pkg}")
                self.package_name = new_pkg
            else:
                return {"error": "Failed to dynamically resolve package name. App may not have installed correctly."}

        # 3b. Extract static metadata dynamically
        print("  [*] Extracting metadata dynamically via dumpsys...")
        results['dynamic_metadata'] = self._extract_dynamic_metadata()

        # DIAGNOSTICS: Check if tcpdump exists and root works
        su_check, out, err = self._adb_shell_sync("su -c 'id'")
        if 'uid=0' not in out.lower():
            return {"error": f"Emulator does not have root access (su failed). Output: {out}"}

        tcp_check, out, err = self._adb_shell_sync("su -c 'which tcpdump'")
        if 'tcpdump' not in out:
            return {"error": f"tcpdump is not installed on the emulator at /system/bin/tcpdump."}

        # 2. Start tcpdump (with subprocess.Popen, not background &)
        print("  [*] Starting packet capture (tcpdump)...")
        self._adb_shell_sync(f"rm -f {self.pcap_device_path}")
        self._adb_shell_sync("rm -f /sdcard/tcpdump_err.log")
        
        # Use -U for unbuffered writing, avoiding the flush issue on crash/kill
        tcpdump_cmd = [
            self.adb_cmd,
            "shell",
            "su",
            "-c",
            f"tcpdump -U -i any -s 0 -w {self.pcap_device_path} >/sdcard/tcpdump_err.log 2>&1"
        ]
        tcpdump_proc = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2) # Allow tcpdump to spin up

        # Verify tcpdump didn't exit immediately
        if tcpdump_proc.poll() is not None:
            _, err_out, _ = self._adb_shell_sync("cat /sdcard/tcpdump_err.log")
            return {"error": f"tcpdump failed to start or crashed immediately. Logs: {err_out.strip()}"}

        # Verify package exists before running monkey
        pm_check, pm_out, _ = self._adb_shell_sync(f"pm list packages | grep {self.package_name}")
        if self.package_name not in pm_out:
             # Try without grep just in case
             pm_check, pm_out, _ = self._adb_shell_sync("pm list packages")
             if self.package_name not in pm_out:
                 return {"error": f"Package {self.package_name} is not installed on the device."}

        # 3. Launch App using Monkey
        print("  [*] Launching app and simulating user interaction...")
        self._run_adb(["shell", "monkey", "-p", self.package_name, "-v", "500"])

        # 4. Wait to gather traffic
        print(f"  [*] Waiting {self.duration} seconds for C2 beacons...")
        time.sleep(self.duration)

        # 5. Stop tcpdump
        print("  [*] Stopping packet capture...")
        tcpdump_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Fallback if Popen terminate fails
            self._adb_shell_sync("su -c 'killall tcpdump'")

        # 6. Verify PCAP exists on device
        ls_check, ls_out, _ = self._adb_shell_sync(f"ls -lh {self.pcap_device_path}")
        print(f"  [DEBUG] PCAP file on device: {ls_out.strip()}")
        if 'No such file' in ls_out or ls_out.strip() == '':
            success, err_out, stderr = self._adb_shell_sync("cat /sdcard/tcpdump_err.log")
            return {"error": f"PCAP was not created on device. tcpdump error: {err_out.strip()}"}

        # 7. Pull PCAP
        print("  [*] Pulling PCAP file...")
        pull_success, pull_stdout, pull_stderr = self._run_adb(["pull", self.pcap_device_path, self.pcap_local_path])
        if not pull_success:
            return {"error": f"Failed to pull PCAP file from device: {pull_stderr}"}

        # 8. Uninstall APK
        print("  [*] Uninstalling APK...")
        self._run_adb(["uninstall", self.package_name])

        # 9. Parse PCAP
        if os.path.exists(self.pcap_local_path):
            print("  [*] Parsing network traffic...")
            parser = PCAPParser(self.pcap_local_path)
            pcap_data = parser.parse()
            results['network_traffic'] = pcap_data
        else:
            results['network_traffic'] = {"error": "PCAP file failed to transfer to host machine."}

        results['status'] = "completed"
        return results
