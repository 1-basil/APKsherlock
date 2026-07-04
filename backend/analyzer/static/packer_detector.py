import os
import math
from pathlib import Path
from typing import Dict, List, Tuple

class PackerDetector:
    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.extracted_dir = os.path.join(output_dir, "extracted")
        
        # Known commercial/malware packers and their artifact signatures
        self.packer_signatures = {
            "libnpdcc.so": "Naga Protect / Nagapt",
            "libsec.so": "DexGuard / Bangcle",
            "libjiagu.so": "Qihoo 360 Jiagu",
            "libjiagu_x86.so": "Qihoo 360 Jiagu",
            "libprotectClass.so": "Tencent Legu",
            "libexec.so": "Tencent Legu",
            "libshell.so": "SecNeo",
            "libDexHelper.so": "SecNeo",
            "libkwscmm.so": "Kiwisec",
            "libapssec.so": "ApkProtect",
            "libapkprotect.so": "ApkProtect",
            "libmobisec.so": "Aliyun",
            "libbaiduprotect.so": "Baidu Protect",
            "aliprotect": "Aliyun Protect",
            "libsgmain.so": "Aliyun Protect",
            "libchaosvmp.so": "ChaosVMP",
            "libigexin.so": "Igexin Payload"
        }
        
    def analyze(self) -> dict:
        results = {
            "is_packed": False,
            "detected_packers": [],
            "encrypted_blobs": [],
            "suspicious_entropy": False
        }
        
        import zipfile
        if not zipfile.is_zipfile(self.apk_path):
            return results
            
        # 1. Scan for packer artifacts in the APK zip tree
        packers_found = set()
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                for info in zf.infolist():
                    filename = Path(info.filename).name
                    if filename in self.packer_signatures:
                        packers_found.add(self.packer_signatures[filename])
                        
                    # 2. Scan assets/ directory for encrypted blobs
                    if "assets/" in info.filename and info.file_size > 100 * 1024:
                        try:
                            # Read blob into memory
                            with zf.open(info.filename) as f:
                                data = f.read()
                                
                            entropy = self._calculate_entropy_from_bytes(data)
                            if entropy > 7.5:
                                results["suspicious_entropy"] = True
                                xor_hits = self._bruteforce_xor_header_bytes(data)
                                
                                results["encrypted_blobs"].append({
                                    "path": info.filename,
                                    "size_kb": round(info.file_size / 1024, 2),
                                    "entropy": round(entropy, 3),
                                    "xor_header_hits": xor_hits
                                })
                        except Exception:
                            pass
        except Exception:
            pass
            
        if packers_found:
            results["is_packed"] = True
            results["detected_packers"] = list(packers_found)
            
        return results
        
    def _calculate_entropy_from_bytes(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data to detect encryption/packing."""
        if not data:
            return 0.0
            
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        
        for byte in data:
            counts[byte] += 1
            
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
                
        return entropy

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of a file to detect encryption/packing."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 100) # Read up to 100KB to sample entropy efficiently
            return self._calculate_entropy_from_bytes(data)
        except Exception:
            return 0.0
            
    def _bruteforce_xor_header_bytes(self, data: bytes) -> List[dict]:
        """Try single byte XOR to see if it decodes to known magic bytes (ZIP or DEX)."""
        hits = []
        if len(data) < 16:
            return hits
            
        header = data[:16]
        magic_signatures = {
            b'PK\x03\x04': 'ZIP / APK / JAR',
            b'dex\n035': 'DEX (Standard)',
            b'dex\n036': 'DEX (Modern)',
            b'dey\n036': 'ODEX',
        }
        
        for key in range(256):
            decoded = bytes(b ^ key for b in header)
            
            for magic, desc in magic_signatures.items():
                if decoded.startswith(magic):
                    hits.append({
                        "key_hex": f"0x{key:02x}",
                        "revealed_type": desc,
                        "decoded_header": str(decoded[:8])
                    })
                    
        return hits

    def _bruteforce_xor_header(self, file_path: str) -> List[dict]:
        """Try single byte XOR to see if it decodes to known magic bytes (ZIP or DEX)."""
        hits = []
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            return self._bruteforce_xor_header_bytes(header)
        except Exception:
            return hits
