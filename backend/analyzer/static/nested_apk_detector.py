import os
import zipfile
import hashlib
import struct
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

class NestedAPKDetector:
    """
    Discovers and analyzes APKs hidden inside APKs.
    
    Techniques used by malware:
    1. Rename APK → .bt / .dat / .png / .so / .db
    2. Store in assets/, raw/, res/ folders
    3. XOR/Base64 encode and decode at runtime
    4. Split across multiple files and reassemble
    5. Store as encrypted blob
    """

    # ZIP magic bytes (APK is a ZIP file)
    ZIP_MAGIC      = b'PK\x03\x04'   # Standard ZIP local file header
    ZIP_MAGIC_SPAN = b'PK\x07\x08'   # Spanning ZIP
    DEX_MAGIC      = b'dex\n'        # DEX bytecode
    ELF_MAGIC      = b'\x7fELF'      # ELF native binary
    PDF_MAGIC      = b'%PDF'
    JAR_MAGIC      = b'PK\x03\x04'   # JAR is also ZIP

    # Extensions that malware uses to hide APKs
    DISGUISED_EXTENSIONS = {
        # Data files
        ".bt",   ".dat",  ".bin",  ".data", ".blob",
        ".raw",  ".dump", ".pak",  ".cache",
        # Media files (to hide in plain sight)
        ".png",  ".jpg",  ".jpeg", ".gif",  ".bmp",
        ".mp3",  ".mp4",  ".wav",  ".ogg",
        # Text files
        ".txt",  ".log",  ".cfg",  ".conf", ".ini",
        ".xml",  ".json", ".html", ".htm",
        # No extension
        "",
    }

    # Folders where malware hides payloads
    SUSPICIOUS_PATHS = [
        "assets/",
        "res/raw/",
        "res/drawable/",
        "lib/",
        "META-INF/",
    ]

    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path    = apk_path
        self.output_dir  = Path(output_dir) / "nested_apks"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings    = []

    def run(self) -> dict:
        """Full nested APK discovery pipeline"""
        print("\n  [*] Starting Nested APK / Payload Discovery...")

        # Pass 1: Magic byte scanning
        print("  [*] Pass 1: Magic byte scan on all files...")
        magic_findings = self._scan_by_magic_bytes()

        # Pass 2: Entropy analysis (detect encrypted payloads)
        print("  [*] Pass 2: Entropy analysis...")
        entropy_findings = self._scan_by_entropy()

        # Pass 3: Concatenated ZIP detection
        print("  [*] Pass 3: Scanning for concatenated ZIPs...")
        concat_findings = self._scan_concatenated_zip()

        # Pass 4: Look for payload assembly patterns in code
        print("  [*] Pass 4: Code pattern analysis...")
        code_findings = self._scan_code_patterns()

        # Combine all findings
        all_payloads = (
            magic_findings +
            entropy_findings +
            concat_findings
        )

        # Deduplicate by hash
        seen_hashes = set()
        unique_payloads = []
        for p in all_payloads:
            h = p.get('sha256', p.get('path', ''))
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_payloads.append(p)

        # Deep analyze each found payload
        analyzed = []
        for payload in unique_payloads:
            print(f"  [*] Deep analyzing: {payload.get('source_path')}")
            deep = self._deep_analyze_payload(payload)
            analyzed.append(deep)

        return {
            "total_hidden_payloads": len(analyzed),
            "payloads":              analyzed,
            "code_patterns":         code_findings,
            "dropper_indicators":    self._assess_dropper_behavior(
                                         analyzed, code_findings
                                     ),
            "summary":               self._build_summary(analyzed, code_findings)
        }

    # ─────────────────────────────────────────────────────────
    # PASS 1: MAGIC BYTE DETECTION
    # ─────────────────────────────────────────────────────────
    def _scan_by_magic_bytes(self) -> list:
        """
        Read first 8 bytes of every file in APK.
        ZIP magic = PK\x03\x04 → could be nested APK/JAR
        """
        findings = []

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for info in zf.infolist():
                # Skip standard APK internals
                if self._is_standard_apk_file(info.filename):
                    continue

                try:
                    # Read first 8 bytes only (efficient)
                    with zf.open(info) as f:
                        header = f.read(8)

                    file_type = self._identify_by_magic(header)
                    if not file_type:
                        continue

                    # Read full file data
                    with zf.open(info) as f:
                        data = f.read()

                    finding = {
                        "source_path":  info.filename,
                        "size_bytes":   info.file_size,
                        "size_kb":      round(info.file_size / 1024, 1),
                        "file_type":    file_type,
                        "magic_bytes":  header[:4].hex(),
                        "detection":    "magic_byte_scan",
                        "data":         data,
                        "md5":          hashlib.md5(data).hexdigest(),
                        "sha256":       hashlib.sha256(data).hexdigest(),
                        "disguise_ext": Path(info.filename).suffix.lower(),
                        "is_disguised": self._is_disguised(
                                            info.filename, file_type
                                        ),
                        "is_primary_payload": False
                    }
                    findings.append(finding)
                    print(f"    🔴 FOUND {file_type}: {info.filename} "
                          f"({finding['size_kb']} KB)")

                except Exception as e:
                    continue

        return findings

    def _identify_by_magic(self, header: bytes) -> Optional[str]:
        """Identify file type from magic bytes"""
        if header[:4] == self.ZIP_MAGIC:
            # Could be APK, JAR, AAB, ZIP
            return "APK/ZIP/JAR"
        if header[:4] == self.DEX_MAGIC:
            return "DEX_BYTECODE"
        if header[:4] == self.ELF_MAGIC:
            return "ELF_BINARY"
        if header[:4] == b'dex\n':
            return "DEX_BYTECODE"
        if header[:3] == self.PDF_MAGIC:
            return "PDF"
        if header[:2] == b'MZ':
            return "PE_EXECUTABLE"   # Windows EXE (unusual in APK)
        if header[:6] == b'\x89PNG\r\n':
            # Real PNG starts with specific bytes
            return None              # Actual PNG, skip
        return None

    def _is_disguised(self, filename: str, actual_type: str) -> bool:
        """Check if file extension doesn't match actual content"""
        ext = Path(filename).suffix.lower()
        if actual_type in ("APK/ZIP/JAR",) and ext not in (".apk", ".jar", ".zip", ".aab"):
            return True
        if actual_type == "DEX_BYTECODE" and ext != ".dex":
            return True
        if actual_type == "ELF_BINARY" and ext != ".so":
            return True
        return False

    def _is_standard_apk_file(self, filename: str) -> bool:
        """Skip standard APK components"""
        standard = [
            "classes.dex", "classes2.dex", "classes3.dex",
            "classes4.dex", "classes5.dex",
            "AndroidManifest.xml", "resources.arsc",
            "META-INF/MANIFEST.MF", "META-INF/CERT.SF",
            "META-INF/CERT.RSA", "META-INF/CERT.DSA",
        ]
        # Skip image files (usually legitimate)
        if filename.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            # BUT still scan if in suspicious path
            if not any(filename.startswith(p) for p in self.SUSPICIOUS_PATHS[:2]):
                return True
        return filename in standard

    # ─────────────────────────────────────────────────────────
    # PASS 2: ENTROPY ANALYSIS
    # ─────────────────────────────────────────────────────────
    def _scan_by_entropy(self) -> list:
        """
        High entropy = encrypted/compressed data
        Encrypted APKs have entropy > 7.5 bits/byte
        Normal code: 4-6 bits/byte
        """
        findings = []

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for info in zf.infolist():
                # Only scan suspicious-path files and unusual extensions
                is_suspicious_path = any(
                    info.filename.startswith(p) for p in self.SUSPICIOUS_PATHS
                )
                is_unusual_ext = Path(info.filename).suffix.lower() in \
                                 self.DISGUISED_EXTENSIONS

                if not (is_suspicious_path or is_unusual_ext):
                    continue

                # Skip tiny files
                if info.file_size < 1024:
                    continue

                try:
                    with zf.open(info) as f:
                        data = f.read()

                    entropy = self._calculate_entropy(data)

                    if entropy > 7.5:
                        # Very high entropy = likely encrypted payload
                        findings.append({
                            "source_path": info.filename,
                            "size_bytes":  info.file_size,
                            "size_kb":     round(info.file_size / 1024, 1),
                            "file_type":   "ENCRYPTED_BLOB",
                            "entropy":     round(entropy, 3),
                            "detection":   "entropy_analysis",
                            "data":        data,
                            "md5":         hashlib.md5(data).hexdigest(),
                            "sha256":      hashlib.sha256(data).hexdigest(),
                            "note":        f"Entropy {entropy:.2f} > 7.5 suggests encryption/compression"
                        })
                        print(f"    🟡 HIGH ENTROPY: {info.filename} "
                              f"(entropy={entropy:.2f}, {info.file_size//1024}KB)")

                    elif 6.5 < entropy <= 7.5:
                        # Medium-high entropy - worth noting
                        print(f"    🟡 MEDIUM-HIGH ENTROPY: {info.filename} "
                              f"(entropy={entropy:.2f})")

                except Exception:
                    continue

        return findings

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        if not data:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        length  = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                prob     = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    # ─────────────────────────────────────────────────────────
    # PASS 3: CONCATENATED ZIP DETECTION
    # ─────────────────────────────────────────────────────────
    def _scan_concatenated_zip(self) -> list:
        """
        Some droppers concatenate multiple ZIP/APK files.
        Scan raw bytes of files for embedded ZIP signatures.
        """
        findings = []

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for info in zf.infolist():
                if info.file_size < 4096:  # Too small
                    continue

                try:
                    with zf.open(info) as f:
                        data = f.read()

                    # Search for ZIP magic bytes AFTER the first 4 bytes
                    # (to skip the file's own ZIP header if it's a ZIP)
                    zip_offsets = self._find_all_occurrences(
                        data, self.ZIP_MAGIC, start=4
                    )

                    if zip_offsets:
                        for offset in zip_offsets:
                            embedded = data[offset:]
                            if self._is_valid_zip(embedded):
                                findings.append({
                                    "source_path": info.filename,
                                    "offset":      offset,
                                    "size_bytes":  len(embedded),
                                    "file_type":   "EMBEDDED_ZIP_IN_FILE",
                                    "detection":   "concatenated_zip",
                                    "data":        embedded,
                                    "md5":         hashlib.md5(embedded).hexdigest(),
                                    "sha256":      hashlib.sha256(embedded).hexdigest(),
                                    "note":        f"ZIP embedded at offset {offset} within {info.filename}"
                                })
                                print(f"    🔴 EMBEDDED ZIP at offset {offset}"
                                      f" in {info.filename}")

                except Exception:
                    continue

        return findings

    def _find_all_occurrences(
        self, data: bytes, pattern: bytes, start: int = 0
    ) -> list:
        """Find all occurrences of a byte pattern"""
        offsets = []
        idx     = start
        while True:
            pos = data.find(pattern, idx)
            if pos == -1:
                break
            offsets.append(pos)
            idx = pos + 1
        return offsets

    def _is_valid_zip(self, data: bytes) -> bool:
        """Check if bytes form a valid ZIP file"""
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                return len(names) > 0
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────
    # PASS 4: CODE PATTERN ANALYSIS
    # ─────────────────────────────────────────────────────────
    def _scan_code_patterns(self) -> list:
        """
        Look for dropper patterns in raw strings:
        - DexClassLoader loading from assets
        - File copy + chmod + exec patterns
        - Base64 decode + write + load
        """
        patterns = {
            "DexClassLoader": {
                "pattern": r'DexClassLoader',
                "severity": "CRITICAL",
                "description": "Dynamically loads DEX from file - classic dropper",
                "forensic": "App loads secondary payload at runtime from disk"
            },
            "PathClassLoader": {
                "pattern": r'PathClassLoader',
                "severity": "HIGH",
                "description": "Loads classes from path - payload loading",
                "forensic": "Secondary code loaded from external path"
            },
            "InMemoryDexClassLoader": {
                "pattern": r'InMemoryDexClassLoader',
                "severity": "CRITICAL",
                "description": "Loads DEX directly from memory bytes - fileless malware",
                "forensic": "Payload executed directly in memory - advanced evasion"
            },
            "assets_open": {
                "pattern": r'(?:getAssets\(\)|AssetManager).*open\(',
                "severity": "HIGH",
                "description": "Opens file from assets folder",
                "forensic": "Likely reading hidden payload from assets"
            },
            "chmod_execute": {
                "pattern": r'chmod\s+(?:777|755|\+x)',
                "severity": "CRITICAL",
                "description": "Makes file executable",
                "forensic": "Preparing payload for execution"
            },
            "copy_and_load": {
                "pattern": r'(?:copy|write).*(?:dex|apk|payload)',
                "severity": "HIGH",
                "description": "Copies and loads a file",
                "forensic": "Dropper extracting payload to disk"
            },
            "reflect_load": {
                "pattern": r'loadClass|forName.*exec',
                "severity": "HIGH",
                "description": "Reflection-based class loading",
                "forensic": "Evades static analysis via reflection"
            },
            "native_load": {
                "pattern": r'System\.load(?:Library)?\(',
                "severity": "HIGH",
                "description": "Loads native library dynamically",
                "forensic": "Could load malicious .so from assets"
            },
            "bt_file_access": {
                "pattern": r'\.bt["\'\s]',
                "severity": "CRITICAL",
                "description": "References .bt files (known payload extension)",
                "forensic": "Directly references hidden payload files found in APK"
            },
            "file_rename": {
                "pattern": r'renameTo|rename.*\.(?:apk|dex)',
                "severity": "HIGH",
                "description": "Renames files - possibly restoring hidden payload name",
                "forensic": "Renames disguised payload back to real extension"
            },
            "install_package": {
                "pattern": r'installPackage|ACTION_INSTALL_PACKAGE|REQUEST_INSTALL',
                "severity": "CRITICAL",
                "description": "Silently installs another APK",
                "forensic": "Dropper installs secondary malware package"
            },
            "xor_decrypt": {
                "pattern": r'(?:XOR|xor|\^=|xorKey|decrypt)',
                "severity": "HIGH",
                "description": "XOR decryption - used to decrypt hidden payloads",
                "forensic": "Payload likely XOR-encrypted in assets"
            },
            "base64_decode_write": {
                "pattern": r'Base64.*decode|decode.*FileOutputStream',
                "severity": "HIGH",
                "description": "Decodes Base64 and writes to file",
                "forensic": "Payload possibly stored as Base64 string"
            },
        }

        found_patterns = []

        try:
            # Extract all strings from APK for pattern scanning
            raw_text = self._get_all_strings()

            for pattern_name, info in patterns.items():
                matches = re.findall(info['pattern'], raw_text, re.IGNORECASE)
                if matches:
                    # Get context
                    contexts = self._get_pattern_contexts(
                        raw_text, info['pattern'], max_contexts=3
                    )
                    found_patterns.append({
                        "pattern":     pattern_name,
                        "severity":    info['severity'],
                        "description": info['description'],
                        "forensic":    info['forensic'],
                        "match_count": len(matches),
                        "contexts":    contexts
                    })

        except Exception as e:
            print(f"    ⚠️  Code pattern scan warning: {e}")

        return found_patterns

    def _get_all_strings(self) -> str:
        """Extract all readable strings from APK"""
        strings_list = []

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith(('.dex', '.xml', '.json', '.js', '.html',
                                  '.bt', '.dat', '.bin', '.txt')):
                    try:
                        data = zf.read(name)
                        # ASCII strings
                        ascii_strs = re.findall(rb'[\x20-\x7E]{4,}', data)
                        strings_list.extend([
                            s.decode('ascii', errors='ignore')
                            for s in ascii_strs
                        ])
                    except Exception:
                        continue

        return '\n'.join(strings_list)

    def _get_pattern_contexts(
        self, text: str, pattern: str, max_contexts: int = 3
    ) -> list:
        """Get surrounding text context for pattern matches"""
        contexts = []
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start = max(0, match.start() - 60)
            end   = min(len(text), match.end() + 60)
            ctx   = text[start:end].replace('\n', ' ').strip()
            contexts.append(ctx)
            if len(contexts) >= max_contexts:
                break
        return contexts

    # ─────────────────────────────────────────────────────────
    # DEEP ANALYSIS OF FOUND PAYLOAD
    # ─────────────────────────────────────────────────────────
    def _deep_analyze_payload(self, payload: dict) -> dict:
        """
        Fully analyze an extracted nested payload.
        If it's an APK - run full static analysis on it too.
        """
        data      = payload.get('data', b'')
        file_type = payload.get('file_type', 'UNKNOWN')

        result = {
            "source_path":  payload.get('source_path'),
            "file_type":    file_type,
            "size_bytes":   len(data),
            "size_kb":      round(len(data) / 1024, 1),
            "hashes": {
                "md5":    payload.get('md5',    hashlib.md5(data).hexdigest()),
                "sha256": payload.get('sha256', hashlib.sha256(data).hexdigest()),
            },
            "entropy":       payload.get('entropy', self._calculate_entropy(data)),
            "detection_method": payload.get('detection'),
            "is_disguised":  payload.get('is_disguised', False),
            "disguise_ext":  payload.get('disguise_ext', ''),
            "analysis":      {}
        }

        # Save payload to disk for further analysis
        safe_name   = payload['source_path'].replace('/', '_').replace('\\', '_')
        # Windows MAX_PATH is 260. Limit filename to avoid issues with deep obfuscated paths
        if len(safe_name) > 150:
            ext = Path(safe_name).suffix
            hash_suffix = hashlib.md5(safe_name.encode('utf-8', errors='ignore')).hexdigest()[:8]
            safe_name = f"{safe_name[:130]}_{hash_suffix}{ext}"
            
        saved_path  = self.output_dir / safe_name
        with open(saved_path, 'wb') as f:
            f.write(data)
        result['extracted_to'] = str(saved_path)

        # ── If it's an APK/ZIP, analyze its contents ──────────
        if file_type in ("APK/ZIP/JAR", "EMBEDDED_ZIP_IN_FILE"):
            result['analysis'] = self._analyze_nested_apk(data, payload['source_path'])

        # ── If it's a DEX file ────────────────────────────────
        elif file_type == "DEX_BYTECODE":
            result['analysis'] = self._analyze_dex(data)

        # ── If it's an encrypted blob ─────────────────────────
        elif file_type == "ENCRYPTED_BLOB":
            result['analysis'] = self._analyze_encrypted_blob(data)

        return result

    def _analyze_nested_apk(self, data: bytes, source_name: str) -> dict:
        """
        Full analysis of a nested APK found inside the parent APK.
        Treats it as a complete APK and extracts all information.
        """
        import io
        import warnings
        warnings.filterwarnings('ignore')

        analysis = {
            "type":              "NESTED_APK",
            "is_valid_zip":      False,
            "file_count":        0,
            "file_tree":         [],
            "has_manifest":      False,
            "has_dex":           False,
            "dex_count":         0,
            "has_native":        False,
            "package_name":      None,
            "permissions":       [],
            "activities":        [],
            "services":          [],
            "receivers":         [],
            "suspicious_files":  [],
            "embedded_strings":  [],
            "iocs":              {},
            "threat_indicators": [],
            "androguard_meta":   None,
        }

        try:
            # Check if valid ZIP
            with zipfile.ZipFile(io.BytesIO(data)) as nested_zf:
                analysis['is_valid_zip'] = True
                names                    = nested_zf.namelist()
                analysis['file_count']   = len(names)

                print(f"\n    📦 Nested APK contains {len(names)} files")

                # Build file tree
                file_tree    = []
                nested_dex   = []
                nested_so    = []
                nested_assets = []
                nested_suspicious = []

                for name in names:
                    ext  = Path(name).suffix.lower()
                    size = nested_zf.getinfo(name).file_size
                    entry = {
                        "path":       name,
                        "size":       size,
                        "type":       _classify_file(name),
                        "suspicious": _is_suspicious(name)
                    }
                    file_tree.append(entry)

                    if name == "AndroidManifest.xml":
                        analysis['has_manifest'] = True
                    if ext == ".dex":
                        nested_dex.append(name)
                        analysis['has_dex'] = True
                    if ext == ".so":
                        nested_so.append(name)
                        analysis['has_native'] = True
                    if "assets/" in name:
                        nested_assets.append(name)
                    if entry['suspicious']:
                        nested_suspicious.append(name)

                analysis['file_tree']       = file_tree
                analysis['dex_count']       = len(nested_dex)
                analysis['dex_files']       = nested_dex
                analysis['native_libs']     = nested_so
                analysis['asset_files']     = nested_assets
                analysis['suspicious_files']= nested_suspicious

                print(f"    📦 Has AndroidManifest: {analysis['has_manifest']}")
                print(f"    📦 DEX files: {nested_dex}")
                print(f"    📦 Native libs: {nested_so}")
                print(f"    📦 Asset files: {nested_assets}")

                # Extract and scan strings from nested APK
                nested_strings = []
                ioc_data       = {}

                for name in names:
                    if name.endswith(('.dex', '.xml', '.js', '.json',
                                      '.html', '.txt', '.bt', '.dat')):
                        try:
                            raw = nested_zf.read(name)
                            strs = re.findall(rb'[\x20-\x7E]{6,}', raw)
                            decoded = [
                                s.decode('ascii', errors='ignore')
                                for s in strs
                            ]
                            nested_strings.extend(decoded)
                        except Exception:
                            continue

                # Run IOC extraction on nested APK strings
                if nested_strings:
                    string_blob = '\n'.join(nested_strings)
                    ioc_data    = self._quick_ioc_scan(string_blob)
                    analysis['iocs'] = ioc_data

                    # Show interesting findings
                    for ioc_type, vals in ioc_data.items():
                        if vals:
                            print(f"    🔴 Nested IOC [{ioc_type}]: "
                                  f"{vals[:3]}")

                # Store interesting strings
                interesting = self._filter_interesting_strings(nested_strings)
                analysis['embedded_strings'] = interesting[:50]

                # Try Androguard on nested APK
                nested_path = self.output_dir / f"nested_{Path(source_name).name}.apk"
                with open(nested_path, 'wb') as nf:
                    nf.write(data)

                try:
                    from androguard.misc import AnalyzeAPK
                    print(f"    [*] Running Androguard on nested APK...")
                    na, nd, ndx = AnalyzeAPK(str(nested_path))

                    nested_meta = {
                        "package_name": na.get_package(),
                        "version":      na.get_androidversion_name(),
                        "min_sdk":      na.get_min_sdk_version(),
                        "target_sdk":   na.get_target_sdk_version(),
                        "permissions":  list(na.get_permissions()),
                        "activities":   list(na.get_activities()),
                        "services":     list(na.get_services()),
                        "receivers":    list(na.get_receivers()),
                        "main_activity":na.get_main_activity(),
                    }
                    analysis['androguard_meta']   = nested_meta
                    analysis['package_name']       = nested_meta['package_name']
                    analysis['permissions']        = nested_meta['permissions']
                    analysis['activities']         = nested_meta['activities']
                    analysis['services']           = nested_meta['services']
                    analysis['receivers']          = nested_meta['receivers']

                    print(f"    📦 Nested Package : {nested_meta['package_name']}")
                    print(f"    📦 Permissions    : {len(nested_meta['permissions'])}")

                    # Permission risk on nested APK
                    if nested_meta['permissions']:
                        sys.path.insert(0, os.path.dirname(
                            os.path.dirname(os.path.abspath(__file__))
                        ))
                        try:
                            from analyzer.static.permission_analyzer import PermissionAnalyzer
                            pa   = PermissionAnalyzer(nested_meta['permissions'])
                            pres = pa.analyze()
                            analysis['permission_risk'] = {
                                "grade":        pres.get('risk_grade'),
                                "score":        pres.get('risk_percentage'),
                                "dangerous":    pres.get('categorized', {}).get('CRITICAL', []),
                                "combinations": pres.get('dangerous_combinations', [])
                            }
                            print(f"    📦 Permission Risk: "
                                  f"{pres.get('risk_grade')} "
                                  f"({pres.get('risk_percentage')}%)")
                        except Exception:
                            pass

                except Exception as ag_err:
                    print(f"    ⚠️  Androguard on nested APK failed: {ag_err}")

                # Threat indicators
                indicators = []
                if analysis['has_manifest'] and analysis['has_dex']:
                    indicators.append({
                        "indicator":   "COMPLETE_NESTED_APK",
                        "severity":    "CRITICAL",
                        "description": "Nested file is a complete Android application",
                        "forensic":    "This is a fully functional hidden APK "
                                       "that can be silently installed"
                    })
                if analysis.get('permissions'):
                    indicators.append({
                        "indicator":   "NESTED_HAS_PERMISSIONS",
                        "severity":    "CRITICAL",
                        "description": f"Nested APK requests "
                                       f"{len(analysis['permissions'])} permissions",
                        "forensic":    "Hidden payload has its own capability set"
                    })
                if ioc_data.get('ipv4_address'):
                    indicators.append({
                        "indicator":   "NESTED_C2_IPS",
                        "severity":    "CRITICAL",
                        "description": "Nested APK contains hardcoded IPs",
                        "forensic":    f"C2 servers: {ioc_data['ipv4_address'][:3]}"
                    })
                if ioc_data.get('domain'):
                    indicators.append({
                        "indicator":   "NESTED_C2_DOMAINS",
                        "severity":    "CRITICAL",
                        "description": "Nested APK contains hardcoded domains",
                        "forensic":    f"Domains: {ioc_data['domain'][:3]}"
                    })

                analysis['threat_indicators'] = indicators

        except zipfile.BadZipFile:
            analysis['error']    = "Not a valid ZIP/APK"
            analysis['raw_note'] = "File may be encrypted or corrupted"
        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def _analyze_dex(self, data: bytes) -> dict:
        """Analyze a standalone DEX file"""
        return {
            "type":       "STANDALONE_DEX",
            "dex_magic":  data[:8].hex(),
            "dex_version":data[4:8].decode('ascii', errors='ignore').strip('\x00'),
            "size":       len(data),
            "note":       "Standalone DEX - dynamically loaded bytecode",
            "forensic":   "This DEX file is loaded at runtime to execute hidden code"
        }

    def _analyze_encrypted_blob(self, data: bytes) -> dict:
        """Analyze an encrypted/obfuscated blob"""
        # Try common decryption methods
        analysis = {
            "type":        "ENCRYPTED_PAYLOAD",
            "size":        len(data),
            "entropy":     round(self._calculate_entropy(data), 3),
            "xor_attempts": [],
            "note":        "Encrypted payload - decryption key in main APK code"
        }

        # Try single-byte XOR with common keys
        common_xor_keys = [0x00, 0x12, 0x34, 0x42, 0x66, 0x7F, 0xAA, 0xFF]
        for key in common_xor_keys:
            decrypted = bytes([b ^ key for b in data[:512]])
            if decrypted[:4] == self.ZIP_MAGIC:
                analysis['xor_attempts'].append({
                    "key":    hex(key),
                    "result": "✅ ZIP/APK found after XOR decryption!",
                    "action": f"XOR decrypt full payload with key {hex(key)}"
                })
            elif decrypted[:4] == self.DEX_MAGIC:
                analysis['xor_attempts'].append({
                    "key":    hex(key),
                    "result": "✅ DEX found after XOR decryption!",
                    "action": f"XOR decrypt full payload with key {hex(key)}"
                })

        return analysis

    # ─────────────────────────────────────────────────────────
    # HELPER METHODS
    # ─────────────────────────────────────────────────────────
    def _quick_ioc_scan(self, text: str) -> dict:
        """Quick IOC scan optimized for nested APK analysis"""
        patterns = {
            "ipv4_address": re.compile(
                r'\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)'
                r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ),
            "domain": re.compile(
                r'\bhttps?://([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]'
                r'(?:\.[a-zA-Z0-9\-]+)+)\b'
            ),
            "url": re.compile(r'https?://[^\s\'"<>]{10,200}'),
            "email": re.compile(
                r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
            ),
            "crypto_btc": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            "api_key": re.compile(
                r'(?i)(?:api[_-]?key|token|secret)\s*[=:]\s*["\']([^"\']{16,})["\']'
            ),
            "phone_india": re.compile(r'(?:\+91|0)?[6789]\d{9}\b'),
        }

        results = {}
        for name, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Deduplicate, clean, filter noise
                clean   = list(set(
                    m if isinstance(m, str) else m[0]
                    for m in matches
                    if len(m if isinstance(m, str) else m[0]) > 4
                    and 'android' not in (m if isinstance(m, str) else m[0]).lower()
                    and 'google' not in (m if isinstance(m, str) else m[0]).lower()
                    and 'schema' not in (m if isinstance(m, str) else m[0]).lower()
                ))
                if clean:
                    results[name] = clean[:20]

        return results

    def _filter_interesting_strings(self, strings: list) -> list:
        """Keep only forensically interesting strings"""
        noise_keywords = [
            "android.", "java.", "javax.", "kotlin.",
            "androidx.", "com.google.", "schema",
            "layout", "string", "drawable", "style",
            "attr", "dimen", "color", "menu",
        ]
        interesting = []
        for s in strings:
            s = s.strip()
            if len(s) < 8 or len(s) > 200:
                continue
            if any(n in s.lower() for n in noise_keywords):
                continue
            if re.match(r'^[a-zA-Z0-9/+=]{20,}$', s):
                # Possible Base64
                interesting.append(f"[POSSIBLE_B64] {s}")
            elif re.match(r'https?://', s):
                interesting.append(f"[URL] {s}")
            elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                interesting.append(f"[IP] {s}")
            elif any(k in s.lower() for k in [
                "key", "token", "secret", "password",
                "admin", "root", "exec", "shell",
                "payload", "inject", "hook"
            ]):
                interesting.append(f"[SENSITIVE] {s}")

        return list(set(interesting))

    def _assess_dropper_behavior(
        self, payloads: list, code_patterns: list
    ) -> dict:
        """Assess overall dropper behavior and severity"""
        severity_score = 0
        indicators     = []

        # Score from payloads found
        for p in payloads:
            analysis = p.get('analysis', {})
            if analysis.get('type') == 'NESTED_APK':
                severity_score += 40
                indicators.append(
                    "Complete nested APK found (full dropper behavior)"
                )
                if analysis.get('permissions'):
                    severity_score += 20
                    indicators.append(
                        f"Nested APK requests {len(analysis['permissions'])} permissions"
                    )
            elif analysis.get('type') == 'ENCRYPTED_PAYLOAD':
                severity_score += 30
                indicators.append("Encrypted payload detected")

        # Score from code patterns
        critical_patterns = [
            "DexClassLoader", "InMemoryDexClassLoader",
            "install_package", "bt_file_access"
        ]
        for cp in code_patterns:
            severity_score += 10
            indicators.append(f"Code pattern: {cp['pattern']} - {cp['description']}")
            if cp['pattern'] in critical_patterns:
                severity_score += 10

        severity_score = min(severity_score, 100)

        return {
            "dropper_confidence": severity_score,
            "classification": (
                "CONFIRMED_DROPPER"  if severity_score >= 70 else
                "LIKELY_DROPPER"     if severity_score >= 40 else
                "POSSIBLE_DROPPER"   if severity_score >= 20 else
                "NOT_DROPPER"
            ),
            "indicators": indicators,
            "explanation": (
                "This APK is designed to install additional malware "
                "at runtime. The main APK acts as a delivery vehicle "
                "for hidden payloads stored in the assets folder. "
                "When executed, it extracts and installs the nested APK."
                if severity_score >= 40 else
                "Limited dropper indicators found."
            )
        }

    def _build_summary(self, payloads: list, code_patterns: list) -> dict:
        return {
            "hidden_payloads_found":  len(payloads),
            "dropper_code_patterns":  len(code_patterns),
            "payload_types":          list(set(
                p.get('file_type', 'UNKNOWN') for p in payloads
            )),
            "total_hidden_size_kb":   sum(
                p.get('size_kb', 0) for p in payloads
            ),
            "critical_findings":      [
                p['source_path'] for p in payloads
                if p.get('is_disguised')
            ]
        }


# ─── Standalone file helpers (reuse from test_analyzer) ──────
def _classify_file(filename: str) -> str:
    ext_map = {
        ".dex": "dalvik_bytecode", ".xml": "xml_resource",
        ".so": "native_library",   ".png": "image",
        ".json": "json_data",      ".db": "database",
        ".html": "html",           ".bt": "SUSPICIOUS_PAYLOAD"
    }
    return ext_map.get(Path(filename).suffix.lower(), "unknown")


def _is_suspicious(filename: str) -> bool:
    fname = filename.lower()
    return any(k in fname for k in [
        "payload", "shell", "inject", "backdoor", "root"
    ]) or fname.endswith(".bt")
