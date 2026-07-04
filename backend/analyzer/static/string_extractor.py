# backend/analyzer/static/string_extractor.py

import re
import base64
from typing import Dict, List, Any
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

class StringExtractor:
    """
    Extracts and analyzes strings from Dex bytecode and Resources.
    Focuses on finding hidden payloads, base64 encoded strings, and interesting paths.
    """

    INTERESTING_PATTERNS = {
        "base64_payloads": re.compile(r'^(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),
        "file_paths": re.compile(r'^/(?:[a-zA-Z0-9_\-\.]+/)+[a-zA-Z0-9_\-\.]+$'),
        "android_paths": re.compile(r'(?:/sdcard|/data/data|/storage/emulated/0)[/\w\.\-]+'),
        "executables": re.compile(r'\b(?:su|sh|bash|toybox|busybox|chmod|chown)\b'),
        "suspicious_words": re.compile(r'(?i)\b(?:hack|exploit|payload|inject|root|backdoor|bypass)\b')
    }

    def __init__(self, apk: APK, dx=None):
        self.apk = apk
        self.dx = dx
        self.raw_strings = []

    def extract(self) -> Dict[str, Any]:
        """Extract strings and analyze them"""
        
        self._extract_from_dex()
        self._extract_from_resources()
        
        # Deduplicate
        self.raw_strings = list(set(self.raw_strings))
        
        analysis_results = self._analyze_strings()
        
        return {
            "total_strings": len(self.raw_strings),
            "findings": analysis_results,
            "raw_strings": self.raw_strings
        }

    def _extract_from_dex(self):
        """Extract all strings from Dex files in the APK"""
        for dex in self.apk.get_all_dex():
            try:
                # DalvikVMFormat parses the dex file
                dvm = DalvikVMFormat(dex)
                for string_val in dvm.get_strings():
                    # string_val is bytes in Python 3 often, try decoding
                    if isinstance(string_val, bytes):
                        try:
                            string_val = string_val.decode('utf-8', errors='ignore')
                        except Exception:
                            continue
                    if isinstance(string_val, str) and len(string_val) >= 4:
                        self.raw_strings.append(string_val)
            except Exception as e:
                print(f"[!] Error extracting strings from a Dex file: {e}")

    def _extract_from_resources(self):
        """Extract strings from Android resources (strings.xml)"""
        arsc = self.apk.get_android_resources()
        if arsc:
            # get_strings() might not directly return all values easily without package/locale parsing
            # However, arsc.get_resolved_strings() returns a dict of resource IDs to values.
            try:
                res_packages = arsc.get_packages_names()
                for package_name in res_packages:
                    # Get all string resources (type 'string')
                    # This depends heavily on Androguard version, fallback to a general approach
                    for string_val in arsc.get_strings_resources():
                        # arsc.get_strings_resources returns the actual string values pool
                        if isinstance(string_val, bytes):
                            try:
                                string_val = string_val.decode('utf-8', errors='ignore')
                            except Exception:
                                continue
                        if isinstance(string_val, str) and len(string_val) >= 4:
                            self.raw_strings.append(string_val)
            except Exception as e:
                print(f"[!] Error extracting from resources: {e}")

    def _analyze_strings(self) -> Dict[str, List[str]]:
        """Run interesting patterns on the extracted strings"""
        findings = {key: [] for key in self.INTERESTING_PATTERNS.keys()}
        findings["decoded_base64"] = []

        for s in self.raw_strings:
            for pattern_name, pattern in self.INTERESTING_PATTERNS.items():
                if pattern.search(s):
                    findings[pattern_name].append(s)
                    
                    # If it's base64, try to decode it to see if it reveals more
                    if pattern_name == "base64_payloads":
                        try:
                            decoded = base64.b64decode(s).decode('utf-8')
                            # Check if the decoded string looks like printable text or a URL
                            if len(decoded) > 3 and all(32 <= ord(c) < 127 for c in decoded):
                                findings["decoded_base64"].append({
                                    "original": s,
                                    "decoded": decoded
                                })
                        except Exception:
                            pass

        # Sort findings by length (often longer strings are more interesting)
        for key in findings:
            if key != "decoded_base64":
                findings[key] = sorted(findings[key], key=len, reverse=True)

        return findings
