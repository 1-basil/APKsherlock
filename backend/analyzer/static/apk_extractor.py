# backend/analyzer/static/apk_extractor.py

import zipfile
import hashlib
import os
import json
from datetime import datetime
from pathlib import Path
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.apk import APK
import subprocess

class APKExtractor:
    """
    Core APK extraction engine
    Handles metadata, file tree, decompilation
    """

    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path   = apk_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._apk = None
        self._dx  = None

    def compute_hashes(self) -> dict:
        """Compute forensic file hashes"""
        hashes = {}
        with open(self.apk_path, 'rb') as f:
            data = f.read()
            hashes['md5']    = hashlib.md5(data).hexdigest()
            hashes['sha1']   = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()
        return hashes

    def get_file_metadata(self) -> dict:
        """Get basic file metadata for forensic record"""
        stat = os.stat(self.apk_path)
        return {
            "filename":      os.path.basename(self.apk_path),
            "size_bytes":    stat.st_size,
            "size_mb":       round(stat.st_size / 1024 / 1024, 2),
            "created_at":    datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at":   datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "analysis_time": datetime.utcnow().isoformat(),
            "hashes":        self.compute_hashes()
        }

    def load_androguard(self):
        """Initialize Androguard analysis"""
        self._apk, self._d, self._dx = AnalyzeAPK(self.apk_path)
        return self._apk, self._d, self._dx

    def extract_apk_metadata(self) -> dict:
        """Extract core APK metadata"""
        if not self._apk:
            self.load_androguard()

        a = self._apk
        return {
            "package_name":       a.get_package(),
            "app_name":           a.get_app_name(),
            "version_name":       a.get_androidversion_name(),
            "version_code":       a.get_androidversion_code(),
            "min_sdk":            a.get_min_sdk_version(),
            "target_sdk":         a.get_target_sdk_version(),
            "max_sdk":            a.get_max_sdk_version(),
            "install_location":   a.get_element('manifest', 'installLocation'),
            "main_activity":      a.get_main_activity(),
            "activities":         a.get_activities(),
            "services":           a.get_services(),
            "receivers":          a.get_receivers(),
            "providers":          a.get_providers(),
            "libraries":          a.get_libraries(),
            "is_valid":           a.is_valid_APK(),
        }

    def extract_raw_contents(self) -> list:
        """Extract all files from APK (ZIP format)"""
        raw_dir = self.output_dir / "raw"
        raw_dir.mkdir(exist_ok=True)

        file_tree = []
        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for info in zf.infolist():
                zf.extract(info, raw_dir)
                file_tree.append({
                    "path":           info.filename,
                    "size_bytes":     info.file_size,
                    "compressed":     info.compress_size,
                    "type":           self._classify_file(info.filename),
                    "is_suspicious":  self._is_suspicious_file(info.filename),
                    "flag":           self._get_file_flag(info.filename)
                })

        return sorted(file_tree, key=lambda x: x['path'])

    def _classify_file(self, filename: str) -> str:
        """Classify file by type for UI display"""
        classifications = {
            ".dex":     "dalvik_bytecode",
            ".xml":     "xml_resource",
            ".so":      "native_library",
            ".png":     "image_asset",
            ".jpg":     "image_asset",
            ".webp":    "image_asset",
            ".json":    "json_data",
            ".db":      "database",
            ".sqlite":  "database",
            ".js":      "javascript",
            ".html":    "html",
            ".jar":     "java_archive",
            ".kotlin":  "kotlin_source",
            ".proto":   "protobuf",
            ".cer":     "certificate",
            ".pem":     "certificate",
            ".p12":     "certificate",
            ".rsa":     "signature",
            ".sf":      "signature_manifest",
            ".mf":      "manifest"
        }
        ext = Path(filename).suffix.lower()
        return classifications.get(ext, "unknown")

    def _is_suspicious_file(self, filename: str) -> bool:
        """Flag files that are suspicious"""
        suspicious_patterns = [
            "payload", "shell", "inject", "exploit",
            "root", "su", "busybox", "backdoor",
            ".so" in filename and "lib" not in filename,
            filename.endswith(".dex") and "classes" not in filename,
        ]
        fname_lower = filename.lower()
        return any(
            isinstance(p, bool) and p or
            isinstance(p, str) and p in fname_lower
            for p in suspicious_patterns
        )

    def _get_file_flag(self, filename: str) -> str:
        """Get investigation flag for file"""
        fname_lower = filename.lower()
        if any(k in fname_lower for k in ["secret", "key", "token", "password", "cred"]):
            return "CREDENTIAL_FILE"
        if fname_lower.endswith((".db", ".sqlite")):
            return "DATABASE_FILE"
        if fname_lower.endswith(".so"):
            return "NATIVE_CODE"
        if "assets" in fname_lower and fname_lower.endswith(".json"):
            return "CONFIG_FILE"
        return None

    def decompile_with_jadx(self) -> dict:
        """Decompile DEX bytecode to Java source"""
        jadx_output = self.output_dir / "decompiled"
        jadx_output.mkdir(exist_ok=True)

        result = subprocess.run(
            [
                "jadx",
                "--deobf",                    # Deobfuscation
                "--show-bad-code",            # Show even bad decompiled code
                "--export-gradle",            # Export as gradle project
                "-d", str(jadx_output),
                self.apk_path
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        java_files = {}
        for java_file in jadx_output.rglob("*.java"):
            try:
                relative = str(java_file.relative_to(jadx_output))
                with open(java_file, 'r', errors='ignore') as f:
                    java_files[relative] = f.read()
            except Exception:
                continue

        return {
            "success":      result.returncode == 0,
            "file_count":   len(java_files),
            "java_files":   java_files,
            "errors":       result.stderr[:1000] if result.stderr else None
        }

    def decompile_smali(self) -> str:
        """Get Smali assembly using apktool"""
        smali_output = self.output_dir / "smali"
        subprocess.run(
            ["apktool", "d", self.apk_path, "-o", str(smali_output), "-f"],
            capture_output=True,
            timeout=120
        )
        return str(smali_output)

    def run_static_extraction(self) -> dict:
        """Complete static extraction pipeline"""
        print("[+] Computing hashes...")
        file_meta = self.get_file_metadata()

        print("[+] Loading Androguard...")
        self.load_androguard()

        print("[+] Extracting APK metadata...")
        apk_meta  = self.extract_apk_metadata()

        print("[+] Building file tree...")
        file_tree = self.extract_raw_contents()

        print("[+] Decompiling with JADX...")
        decompiled = self.decompile_with_jadx()

        print("[+] Building Smali...")
        smali_path = self.decompile_smali()

        return {
            "file_metadata": file_meta,
            "apk_metadata":  apk_meta,
            "file_tree":     file_tree,
            "decompiled":    decompiled,
            "smali_path":    smali_path,
            "androguard":    {
                "apk": self._apk,
                "dx":  self._dx
            }
        }
