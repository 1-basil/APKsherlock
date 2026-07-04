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
        
        if not os.path.exists(self.extracted_dir):
            return results
            
        # 1. Scan for packer artifacts in the extracted file tree
        packers_found = set()
        for root, _, files in os.walk(self.extracted_dir):
            for file in files:
                if file in self.packer_signatures:
                    packers_found.add(self.packer_signatures[file])
                    
        if packers_found:
            results["is_packed"] = True
            results["detected_packers"] = list(packers_found)
            
        # 2. Scan assets/ directory for encrypted blobs
        assets_dir = os.path.join(self.extracted_dir, "assets")
        if os.path.exists(assets_dir):
            for root, _, files in os.walk(assets_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.extracted_dir).replace("\\", "/")
                    
                    try:
                        size_bytes = os.path.getsize(file_path)
                        # We only care about somewhat large blobs (e.g. > 100KB)
                        if size_bytes > 100 * 1024:
                            entropy = self._calculate_entropy(file_path)
                            
                            # High entropy usually indicates encryption/packing
                            # Entropy > 7.5 out of 8 is considered highly compressed/encrypted
                            if entropy > 7.5:
                                results["suspicious_entropy"] = True
                                
                                # 3. Attempt XOR brute force on headers
                                xor_hits = self._bruteforce_xor_header(file_path)
                                
                                results["encrypted_blobs"].append({
                                    "path": rel_path,
                                    "size_kb": round(size_bytes / 1024, 2),
                                    "entropy": round(entropy, 3),
                                    "xor_header_hits": xor_hits
                                })
                    except Exception:
                        pass
                        
        return results
        
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of a file to detect encryption/packing."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 100) # Read up to 100KB to sample entropy efficiently
                
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
        except Exception:
            return 0.0
            
    def _bruteforce_xor_header(self, file_path: str) -> List[dict]:
        """Try single byte XOR to see if it decodes to known magic bytes (ZIP or DEX)."""
        hits = []
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            if len(header) < 16:
                return hits
                
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
        except Exception:
            return hits
