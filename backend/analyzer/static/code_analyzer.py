# backend/analyzer/static/code_analyzer.py

import re
from typing import Dict, List, Any

class CodeAnalyzer:
    """
    Analyzes decompiled Java and Smali code for risky API usage,
    malware capabilities, and obfuscation techniques.
    """

    # Definitions of risky API categories and their regex patterns
    RISKY_APIS = {
        "cryptography": {
            "patterns": [
                r"javax\.crypto\.", 
                r"java\.security\.",
                r"MessageDigest\.getInstance",
                r"Cipher\.getInstance",
                r"SecretKeySpec"
            ],
            "capability": "Data Encryption / Decryption",
            "risk": "MEDIUM",
            "desc": "App uses cryptographic functions. Could be protecting C2 traffic or ransomware behavior."
        },
        "reflection": {
            "patterns": [
                r"java\.lang\.reflect\.",
                r"Class\.forName",
                r"Method\.invoke"
            ],
            "capability": "Dynamic Code Loading",
            "risk": "HIGH",
            "desc": "App uses reflection to dynamically invoke methods. Common technique to hide malicious behavior from static analysis."
        },
        "dynamic_class_loading": {
            "patterns": [
                r"dalvik\.system\.DexClassLoader",
                r"dalvik\.system\.PathClassLoader",
                r"java\.net\.URLClassLoader"
            ],
            "capability": "Payload Dropper / Plugin Execution",
            "risk": "CRITICAL",
            "desc": "App loads additional classes at runtime. Extremely common in malware droppers to execute payloads."
        },
        "native_code": {
            "patterns": [
                r"System\.loadLibrary",
                r"System\.load",
                r"\bnative\s+\w+\s+\w+\("
            ],
            "capability": "Native Execution",
            "risk": "MEDIUM",
            "desc": "App loads native libraries (.so). Malicious logic could be hidden in native code."
        },
        "command_execution": {
            "patterns": [
                r"Runtime\.getRuntime\(\)\.exec",
                r"ProcessBuilder"
            ],
            "capability": "OS Command Execution",
            "risk": "CRITICAL",
            "desc": "App executes system commands. Indicates potential root exploits or backdoor behavior."
        },
        "network_obfuscation": {
            "patterns": [
                r"javax\.net\.ssl\.TrustManager",
                r"AllowAllHostnameVerifier",
                r"setHostnameVerifier"
            ],
            "capability": "SSL Pinning Bypass / MitM",
            "risk": "HIGH",
            "desc": "App uses custom trust managers, potentially bypassing SSL verification or intercepting traffic."
        },
        "sms_operations": {
            "patterns": [
                r"android\.telephony\.SmsManager",
                r"sendTextMessage",
                r"sendMultipartTextMessage"
            ],
            "capability": "SMS Sending",
            "risk": "HIGH",
            "desc": "App programmatic sends SMS. Can be used for premium-rate SMS fraud."
        }
    }

    def __init__(self, java_files: Dict[str, str], smali_path: str = None):
        self.java_files = java_files
        self.smali_path = smali_path

        # Pre-compile regex patterns
        for cat in self.RISKY_APIS.values():
            cat["compiled_patterns"] = [re.compile(p) for p in cat["patterns"]]

    def analyze(self) -> Dict[str, Any]:
        """Run code analysis on the provided Java sources"""
        api_findings = self._scan_risky_apis()
        obfuscation_info = self._detect_obfuscation()

        # Calculate a simple code risk score based on findings
        total_risk = 0
        for cat, hits in api_findings.items():
            if hits:
                risk_level = self.RISKY_APIS[cat]["risk"]
                if risk_level == "CRITICAL": total_risk += 10
                elif risk_level == "HIGH": total_risk += 7
                elif risk_level == "MEDIUM": total_risk += 4
                elif risk_level == "LOW": total_risk += 1

        if obfuscation_info["is_obfuscated"]:
            total_risk += 5

        return {
            "risky_api_findings": api_findings,
            "obfuscation": obfuscation_info,
            "code_risk_score": total_risk,
            "capabilities": self._map_capabilities(api_findings)
        }

    def _scan_risky_apis(self) -> Dict[str, List[Dict[str, str]]]:
        """Scan Java files for risky API usage"""
        findings = {cat: [] for cat in self.RISKY_APIS.keys()}

        for filepath, content in self.java_files.items():
            # Quick check if file is likely to contain anything
            for cat_name, cat_data in self.RISKY_APIS.items():
                for pattern in cat_data["compiled_patterns"]:
                    # Find all matches
                    matches = pattern.finditer(content)
                    for match in matches:
                        # Get a bit of context around the match
                        start = max(0, match.start() - 40)
                        end = min(len(content), match.end() + 40)
                        context = content[start:end].strip().replace('\n', ' ')

                        findings[cat_name].append({
                            "file": filepath,
                            "match": match.group(0),
                            "context": context
                        })
        
        # Deduplicate findings per category/file to reduce noise
        for cat_name in findings:
            unique_findings = []
            seen = set()
            for finding in findings[cat_name]:
                sig = f"{finding['file']}:{finding['match']}"
                if sig not in seen:
                    seen.add(sig)
                    unique_findings.append(finding)
            findings[cat_name] = unique_findings

        return findings

    def _detect_obfuscation(self) -> Dict[str, Any]:
        """Detect common obfuscation patterns in class names and structures"""
        # Obfuscators like ProGuard or DexGuard rename classes to a, b, c, etc.
        short_names_count = 0
        total_classes = len(self.java_files)
        
        # Detect packers by looking for known packer stubs (often in Application classes)
        # Some known packer package structures or class names
        known_packers = {
            "com.secneo": "SecNeo",
            "com.tencent.StubShell": "Tencent Legu",
            "com.qihoo.util": "Qihoo 360",
            "s.h.e.l.l": "SecNeo / DexProtector",
            "com.ali.mobisec": "AliPay",
            "com.sec.app": "DexGuard"
        }
        
        detected_packers = []

        for filepath in self.java_files.keys():
            # Check short names (e.g., a.java, a/b/c.java)
            parts = filepath.split('/')
            filename = parts[-1].replace('.java', '')
            
            if len(filename) <= 2:
                short_names_count += 1
                
            # Check for packer signatures in paths
            path_str = filepath.replace('/', '.')
            for packer_sig, packer_name in known_packers.items():
                if packer_sig in path_str and packer_name not in detected_packers:
                    detected_packers.append(packer_name)

        is_obfuscated = False
        obfuscation_percentage = 0
        
        if total_classes > 0:
            obfuscation_percentage = (short_names_count / total_classes) * 100
            # If more than 20% of classes have 1-2 character names, it's highly likely obfuscated
            if obfuscation_percentage > 20:
                is_obfuscated = True

        return {
            "is_obfuscated": is_obfuscated or len(detected_packers) > 0,
            "obfuscated_class_ratio": f"{short_names_count}/{total_classes}",
            "obfuscation_percentage": round(obfuscation_percentage, 2),
            "detected_packers": detected_packers
        }

    def _map_capabilities(self, api_findings: Dict[str, List[Dict[str, str]]]) -> List[Dict[str, str]]:
        """Map API findings to high-level capabilities for the report"""
        capabilities = []
        for cat_name, findings in api_findings.items():
            if findings:
                cat_info = self.RISKY_APIS[cat_name]
                capabilities.append({
                    "capability": cat_info["capability"],
                    "risk": cat_info["risk"],
                    "description": cat_info["desc"],
                    "evidence_count": len(findings)
                })
        return sorted(capabilities, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["risk"], 4))
