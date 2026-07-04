import frida
import time
import json
import subprocess
import threading

FRIDA_HOOK_SCRIPT = """
Java.perform(function () {
    console.log("[*] ForensicDroid Frida Hooks Active...");

    // 1. Hook HTTP / HTTPS Traffic (Bypasses SSL Pinning)
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function (url) {
            send({type: "NETWORK_URL", data: url});
            return this.$init(url);
        };
    } catch (e) {
        console.log("Error hooking URL: " + e);
    }

    // 2. Hook AES / Cryptography Keys & Plaintext
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function (bytes) {
            var result = this.doFinal(bytes);
            send({type: "CRYPTO_OPERATION", algo: this.getAlgorithm()});
            return result;
        };
    } catch (e) {
        console.log("Error hooking Cipher: " + e);
    }

    // 3. Hook Dynamic Code Loading (Droppers / NP Manager)
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            send({type: "DYNAMIC_DEX_LOAD", path: dexPath});
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("Error hooking DexClassLoader: " + e);
    }
    
    // 4. Hook JNI System.loadLibrary
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.loadLibrary0.implementation = function (classLoader, libraryName) {
            send({type: "NATIVE_LIBRARY_LOAD", data: libraryName});
            return this.loadLibrary0(classLoader, libraryName);
        };
    } catch (e) {
        console.log("Error hooking loadLibrary: " + e);
    }
});
"""

class FridaDynamicAnalyzer:
    def __init__(self, package_name: str, duration: int = 30):
        self.package_name = package_name
        self.duration = duration
        self.events = []
        self.session = None
        self.device = None
        self.pid = None

    def _on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            self.events.append(payload)
            print(f"  🧠 [FRIDA EVENT] {payload.get('type')}: {payload.get('data') or payload.get('path') or payload.get('algo')}")
        elif message['type'] == 'error':
            print(f"  ❌ [FRIDA ERROR] {message['description']}")

    def _monitor(self):
        try:
            # Connect to ADB device
            self.device = frida.get_usb_device(timeout=10)
            
            print(f"  [*] Frida spawning '{self.package_name}'...")
            # Spawn application in suspended state
            self.pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(self.pid)
            
            # Inject Hook Script
            script = self.session.create_script(FRIDA_HOOK_SCRIPT)
            script.on('message', self._on_message)
            script.load()
            
            # Resume execution
            self.device.resume(self.pid)
            print(f"  [*] Frida attached and monitoring for {self.duration} seconds...")
            
            # Keep alive for duration
            time.sleep(self.duration)
            
        except frida.ServerNotRunningError:
            print("  ⚠️ Frida server is not running on the device. Hooking skipped.")
        except frida.ExecutableNotFoundError:
            print(f"  ⚠️ Package '{self.package_name}' not found on device.")
        except Exception as e:
            print(f"  ❌ Frida Hooking Failed: {e}")
        finally:
            self._cleanup()

    def _cleanup(self):
        try:
            if self.session:
                self.session.detach()
            if self.device and self.pid:
                self.device.kill(self.pid)
        except Exception:
            pass

    def run_analysis_async(self):
        """Starts Frida hooking in a background thread."""
        self.thread = threading.Thread(target=self._monitor)
        self.thread.start()
        
    def wait(self):
        """Waits for the Frida thread to complete and returns events."""
        if hasattr(self, 'thread'):
            self.thread.join(timeout=self.duration + 5)
        
        return {
            "status": "SUCCESS" if len(self.events) > 0 else "COMPLETED_EMPTY",
            "events_captured": len(self.events),
            "events": self.events
        }
