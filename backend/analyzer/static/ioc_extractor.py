# backend/analyzer/static/ioc_extractor.py

import re
import hashlib
from typing import Dict, List
from pathlib import Path

class IOCExtractor:
    """
    Extracts all Indicators of Compromise from decompiled code
    Specifically designed for law enforcement investigation
    """

    # ─── Regex Patterns ──────────────────────────────────────
    PATTERNS = {
        # Network Indicators
        "ipv4_address": re.compile(
            r'\b(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)'
            r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        "ipv6_address": re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|io|co|in|gov|edu|biz|info|online|site|'
            r'xyz|top|live|shop|store|app|dev|tech|cloud|data|api)\b'
        ),
        "url_full": re.compile(
            r'https?://[^\s\'"<>{}|\\^`\[\]]{4,500}'
        ),
        "api_endpoint": re.compile(
            r'(?:"|\')/(?:api|v\d+|rest|graphql|endpoint|ws|wss)'
            r'[/\w\-\.]+(?:"|\')'
        ),
        "websocket_url": re.compile(
            r'wss?://[^\s\'"<>]+',
            re.IGNORECASE
        ),
        "onion_address": re.compile(
            r'[a-z2-7]{16,56}\.onion',
            re.IGNORECASE
        ),

        # Authentication Artifacts
        "jwt_token": re.compile(
            r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        ),
        "bearer_token": re.compile(
            r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+',
        ),
        "api_key_generic": re.compile(
            r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*'
            r'["\']([a-zA-Z0-9_\-\.]{16,})["\']'
        ),
        "google_api_key": re.compile(
            r'AIza[0-9A-Za-z\-_]{35}'
        ),
        "aws_access_key": re.compile(
            r'AKIA[0-9A-Z]{16}'
        ),
        "aws_secret": re.compile(
            r'(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*'
            r'["\']([a-zA-Z0-9/+]{40})["\']'
        ),
        "firebase_key": re.compile(
            r'https://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com'
        ),
        "firebase_config": re.compile(
            r'firebase[_-]?(?:api[_-]?key|project[_-]?id|'
            r'app[_-]?id)\s*[=:]\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        ),
        "discord_webhook": re.compile(
            r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'
        ),
        "telegram_token": re.compile(
            r'\b\d{8,11}:[A-Za-z0-9_-]{35}\b'
        ),

        # Financial Indicators
        # NOTE: Bitcoin regex is intentionally broad; real validation
        # happens in _validate_bitcoin_address() post-extraction
        "crypto_bitcoin": re.compile(
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        ),
        "crypto_ethereum": re.compile(
            r'\b0x[a-fA-F0-9]{40}\b'
        ),
        "crypto_monero": re.compile(
            r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        ),
        "crypto_solana": re.compile(
            r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'
        ),
        "crypto_tron": re.compile(
            r'\bT[A-Za-z1-9]{33}\b'
        ),

        # Personal Data Indicators
        "email_address": re.compile(
            r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
        ),
        # Phone numbers: require explicit + prefix OR separator characters
        # to avoid matching random digit sequences
        "phone_number": re.compile(
            r'\+\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        ),
        # Indian mobile: require +91 prefix to avoid false positives
        "indian_mobile": re.compile(
            r'\+91[-.\s]?[6789]\d{9}\b'
        ),

        # Credential Patterns
        "hardcoded_password": re.compile(
            r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*'
            r'["\']([^"\']{4,})["\']'
        ),
        "hardcoded_username": re.compile(
            r'(?i)(?:username|user_name|uname|login)\s*[=:]\s*'
            r'["\']([^"\']{2,})["\']'
        ),
        "private_key": re.compile(
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'
        ),
        "secret_key_generic": re.compile(
            r'(?i)(?:secret[_-]?key|signing[_-]?key|'
            r'encryption[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']'
        ),

        # C2 Indicators
        "c2_port": re.compile(
            r'(?:port|PORT)\s*[=:]\s*(\b(?:4444|1234|8888|9999|'
            r'31337|6667|6666|1337|7777|2222|3333|5555|8443)\b)'
        ),
        "base64_suspicious": re.compile(
            r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|'
            r'[A-Za-z0-9+/]{3}=)?'
        ),

        # Server/Infrastructure
        "database_connection": re.compile(
            r'(?i)(?:mongodb|mysql|postgresql|redis|jdbc)'
            r'://[^\s\'"<>]+'
        ),
        "ssh_key": re.compile(
            r'ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/]+'
        ),
    }

    # ─── IOC Categories for Forensic Report ──────────────────
    IOC_FORENSIC_CATEGORIES = {
        "ipv4_address":         ("Network Infrastructure", "CRITICAL"),
        "domain":               ("Network Infrastructure", "HIGH"),
        "url_full":             ("API/Server Communication", "HIGH"),
        "api_endpoint":         ("API Endpoints",           "MEDIUM"),
        "websocket_url":        ("Real-time C2 Channel",    "CRITICAL"),
        "onion_address":        ("Dark Web Infrastructure", "CRITICAL"),
        "jwt_token":            ("Authentication Token",    "CRITICAL"),
        "api_key_generic":      ("API Credential",          "CRITICAL"),
        "google_api_key":       ("Google API Credential",   "HIGH"),
        "aws_access_key":       ("AWS Credential",          "CRITICAL"),
        "firebase_key":         ("Firebase Backend",        "HIGH"),
        "discord_webhook":     ("Discord Webhook Link",    "CRITICAL"),
        "telegram_token":      ("Telegram Bot Token",      "CRITICAL"),
        "crypto_bitcoin":       ("Crypto Wallet (BTC)",     "CRITICAL"),
        "crypto_ethereum":      ("Crypto Wallet (ETH)",     "CRITICAL"),
        "crypto_monero":        ("Crypto Wallet (XMR)",     "CRITICAL"),
        "crypto_solana":        ("Crypto Wallet (SOL)",     "CRITICAL"),
        "crypto_tron":          ("Crypto Wallet (TRX)",     "CRITICAL"),
        "email_address":        ("Developer/Contact Email", "HIGH"),
        "phone_number":         ("Contact Number",          "MEDIUM"),
        "indian_mobile":        ("Indian Mobile Number",    "HIGH"),
        "hardcoded_password":   ("Hardcoded Credential",    "CRITICAL"),
        "private_key":          ("Private Key",             "CRITICAL"),
        "database_connection":  ("Database Connection",     "CRITICAL"),
        "c2_port":              ("Suspicious C2 Port",      "CRITICAL"),
    }

    def __init__(self, java_files: Dict[str, str], raw_strings: List[str] = None):
        self.java_files  = java_files
        self.raw_strings = raw_strings or []
        self.findings    = {}

    def extract_all(self) -> dict:
        """Run all IOC extraction patterns"""
        all_iocs = {}

        # Extract from Java source files
        for filename, content in self.java_files.items():
            file_iocs = self._extract_from_text(content, filename)
            self._merge_iocs(all_iocs, file_iocs)

        # Extract from raw string dump
        for raw_string in self.raw_strings:
            raw_iocs = self._extract_from_text(raw_string, "strings.xml")
            self._merge_iocs(all_iocs, raw_iocs)

        # Enrich with forensic metadata
        enriched = self._enrich_iocs(all_iocs)

        # Deduplicate and prioritize
        return self._prioritize(enriched)

    # Known false-positive email domains from libraries/SDKs
    _EMAIL_FP_DOMAINS = {
        'openssh.com', 'jcraft.com', 'apache.org', 'example.com',
        'example.org', 'example.net', 'localhost', 'android.com',
        'google.com', 'w3.org', 'xmlpull.org', 'xml.org',
    }

    def _extract_from_text(self, text: str, source_file: str) -> dict:
        """Extract all IOC patterns from a text"""
        results = {}
        for ioc_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                if ioc_type not in results:
                    results[ioc_type] = []
                for match in matches:
                    value = match if isinstance(match, str) else match[0]
                    if len(value) > 3:  # Filter noise
                        # Post-extraction validation
                        if not self._validate_ioc(ioc_type, value):
                            continue
                        results[ioc_type].append({
                            "value":  value.strip('"\'\''),
                            "source": source_file,
                            "context": self._get_context(text, value)
                        })
        return results

    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        """Post-extraction validation to eliminate false positives"""
        if ioc_type == 'crypto_bitcoin':
            return self._validate_bitcoin_address(value)
        if ioc_type == 'crypto_ethereum':
            # Must be exactly 42 chars (0x + 40 hex)
            return len(value) == 42
        if ioc_type == 'email_address':
            domain = value.rsplit('@', 1)[-1].lower()
            return domain not in self._EMAIL_FP_DOMAINS
        if ioc_type == 'base64_suspicious':
            # Must be at least 60 chars to be meaningful
            return len(value) >= 60
        return True

    @staticmethod
    def _validate_bitcoin_address(addr: str) -> bool:
        """Validate Bitcoin address using Base58Check checksum.
        Returns True only if the address has a valid checksum."""
        b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        try:
            # Decode Base58
            n = 0
            for char in addr:
                n = n * 58 + b58_alphabet.index(char)
            # Convert to bytes (25 bytes for a standard BTC address)
            raw = n.to_bytes(25, byteorder='big')
            # Last 4 bytes are the checksum
            payload, checksum = raw[:-4], raw[-4:]
            # Verify: double SHA-256 of payload, first 4 bytes must match
            expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            return checksum == expected
        except (ValueError, OverflowError):
            return False

    def _get_context(self, text: str, value: str, window: int = 100) -> str:
        """Get surrounding code context for the IOC"""
        idx = text.find(value)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end   = min(len(text), idx + len(value) + window)
        return text[start:end].strip()

    def _merge_iocs(self, target: dict, source: dict):
        """Merge IOC dictionaries"""
        for ioc_type, findings in source.items():
            if ioc_type not in target:
                target[ioc_type] = []
            target[ioc_type].extend(findings)

    def _enrich_iocs(self, iocs: dict) -> dict:
        """Add forensic metadata to each IOC"""
        enriched = {}
        for ioc_type, findings in iocs.items():
            category, severity = self.IOC_FORENSIC_CATEGORIES.get(
                ioc_type, ("Other", "MEDIUM")
            )
            # Deduplicate by value
            seen   = set()
            unique = []
            for f in findings:
                if f["value"] not in seen:
                    seen.add(f["value"])
                    unique.append({
                        **f,
                        "ioc_type":      ioc_type,
                        "category":      category,
                        "severity":      severity,
                        "investigation_note": self._get_investigation_note(
                            ioc_type, f["value"]
                        )
                    })
            enriched[ioc_type] = unique
        return enriched

    def _get_investigation_note(self, ioc_type: str, value: str) -> str:
        """Generate investigation-specific notes"""
        notes = {
            "ipv4_address":        f"Verify hosting provider via WHOIS. Check if {value} is a known C2.",
            "onion_address":       f"Dark web endpoint detected. Requires Tor investigation: {value}",
            "crypto_bitcoin":      f"Bitcoin wallet {value} - trace via blockchain explorer",
            "crypto_ethereum":     f"Ethereum address {value} - trace via Etherscan",
            "crypto_monero":       f"Monero wallet detected - privacy coin, harder to trace",
            "aws_access_key":      f"AWS key exposed - check CloudTrail logs for usage",
            "hardcoded_password":  f"Hardcoded credential found - check server access logs",
            "database_connection": f"Direct DB connection string - indicates server access",
            "private_key":         f"CRITICAL: Private key exposed - all communications compromised",
            "websocket_url":       f"WebSocket suggests real-time C2 communication channel",
        }
        return notes.get(ioc_type, "Investigate and correlate with network traffic")

    def _prioritize(self, iocs: dict) -> dict:
        """Sort and prioritize IOCs by severity"""
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_iocs    = {}

        for ioc_type in sorted(
            iocs.keys(),
            key=lambda x: priority_order.get(
                self.IOC_FORENSIC_CATEGORIES.get(x, ("", "MEDIUM"))[1], 2
            )
        ):
            sorted_iocs[ioc_type] = iocs[ioc_type]

        return {
            "iocs":           sorted_iocs,
            "summary": {
                "total_iocs":      sum(len(v) for v in iocs.values()),
                "critical_count":  sum(
                    len(v) for k, v in iocs.items()
                    if self.IOC_FORENSIC_CATEGORIES.get(k, ("","MEDIUM"))[1] == "CRITICAL"
                ),
                "ioc_types_found": list(sorted_iocs.keys()),
                "has_c2_indicators": any(
                    k in iocs for k in
                    ["ipv4_address", "websocket_url", "onion_address", "c2_port", "discord_webhook", "telegram_token"]
                ),
                "has_financial_indicators": any(
                    k in iocs for k in
                    ["crypto_bitcoin", "crypto_ethereum", "crypto_monero", "crypto_solana", "crypto_tron"]
                ),
            }
        }
