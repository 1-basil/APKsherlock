# backend/analyzer/static/permission_analyzer.py

from dataclasses import dataclass
from typing import List, Dict

@dataclass
class PermissionInfo:
    name:           str
    risk_level:     str   # CRITICAL / DANGEROUS / NORMAL / SIGNATURE
    risk_score:     int   # 0-10
    category:       str
    description:    str
    forensic_note:  str   # What this means for investigation
    abuse_scenario: str   # How it can be abused

# ─── Master Permission Database ──────────────────────────────
PERMISSION_DATABASE = {
    # CRITICAL - Highest risk, direct data theft potential
    "android.permission.READ_CONTACTS": PermissionInfo(
        name="READ_CONTACTS",
        risk_level="CRITICAL",
        risk_score=9,
        category="Data Theft",
        description="Read all contacts stored on device",
        forensic_note="Apps with this permission can exfiltrate entire contact database",
        abuse_scenario="Steal contact list for spam/phishing/identity theft"
    ),
    "android.permission.READ_SMS": PermissionInfo(
        name="READ_SMS",
        risk_level="CRITICAL",
        risk_score=10,
        category="Data Theft / OTP Bypass",
        description="Read all SMS messages",
        forensic_note="CRITICAL - Can intercept OTPs, banking codes, 2FA tokens",
        abuse_scenario="Read OTP codes for banking fraud, intercept verification codes"
    ),
    "android.permission.RECEIVE_SMS": PermissionInfo(
        name="RECEIVE_SMS",
        risk_level="CRITICAL",
        risk_score=10,
        category="OTP Interception",
        description="Intercept incoming SMS messages in real-time",
        forensic_note="CRITICAL - Real-time OTP interception for financial fraud",
        abuse_scenario="Automatically forward OTPs to C2 server for banking fraud"
    ),
    "android.permission.SEND_SMS": PermissionInfo(
        name="SEND_SMS",
        risk_level="CRITICAL",
        risk_score=9,
        category="Financial Fraud",
        description="Send SMS messages (can incur charges)",
        forensic_note="Can send SMS to premium numbers, spread malware via SMS",
        abuse_scenario="Send SMS to premium rate numbers, spread via victim's contacts"
    ),
    "android.permission.RECORD_AUDIO": PermissionInfo(
        name="RECORD_AUDIO",
        risk_level="CRITICAL",
        risk_score=9,
        category="Surveillance",
        description="Record audio using device microphone",
        forensic_note="Enables covert audio surveillance / eavesdropping",
        abuse_scenario="Record private conversations, meetings, phone calls"
    ),
    "android.permission.CAMERA": PermissionInfo(
        name="CAMERA",
        risk_level="CRITICAL",
        risk_score=9,
        category="Surveillance",
        description="Access device camera",
        forensic_note="Enables covert photo/video surveillance",
        abuse_scenario="Take photos/videos without user knowledge for blackmail"
    ),
    "android.permission.ACCESS_FINE_LOCATION": PermissionInfo(
        name="ACCESS_FINE_LOCATION",
        risk_level="CRITICAL",
        risk_score=8,
        category="Surveillance / Tracking",
        description="Precise GPS location access",
        forensic_note="Enables precise real-time location tracking of victim",
        abuse_scenario="Track victim's movements, stalk, sell location data"
    ),
    "android.permission.READ_CALL_LOG": PermissionInfo(
        name="READ_CALL_LOG",
        risk_level="CRITICAL",
        risk_score=8,
        category="Data Theft",
        description="Read device call history",
        forensic_note="Reveals victim's communication patterns and contacts",
        abuse_scenario="Map victim's social network, identify high-value targets"
    ),
    "android.permission.PROCESS_OUTGOING_CALLS": PermissionInfo(
        name="PROCESS_OUTGOING_CALLS",
        risk_level="CRITICAL",
        risk_score=9,
        category="Call Hijacking",
        description="Intercept and redirect outgoing calls",
        forensic_note="Can redirect calls to premium numbers or intercept",
        abuse_scenario="Call fraud, redirect bank calls to fake support"
    ),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionInfo(
        name="READ_EXTERNAL_STORAGE",
        risk_level="DANGEROUS",
        risk_score=7,
        category="Data Access",
        description="Read all files on external storage",
        forensic_note="Can exfiltrate photos, documents, downloads",
        abuse_scenario="Steal photos, documents, download history"
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionInfo(
        name="WRITE_EXTERNAL_STORAGE",
        risk_level="DANGEROUS",
        risk_score=7,
        category="Data Manipulation",
        description="Write files to external storage",
        forensic_note="Can plant files, modify documents, drop malware",
        abuse_scenario="Drop malware files, modify victim documents"
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionInfo(
        name="SYSTEM_ALERT_WINDOW",
        risk_level="DANGEROUS",
        risk_score=8,
        category="Overlay Attack",
        description="Draw overlays over other apps",
        forensic_note="CRITICAL - Used for credential overlay attacks (banking fraud)",
        abuse_scenario="Show fake login screens over banking apps to steal credentials"
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionInfo(
        name="BIND_ACCESSIBILITY_SERVICE",
        risk_level="CRITICAL",
        risk_score=10,
        category="Device Control",
        description="Full accessibility service control",
        forensic_note="CRITICAL - Enables full device control, keystroke logging",
        abuse_scenario="Log all keystrokes, auto-click, bypass security prompts"
    ),
    "android.permission.BIND_DEVICE_ADMIN": PermissionInfo(
        name="BIND_DEVICE_ADMIN",
        risk_level="CRITICAL",
        risk_score=10,
        category="Device Admin / Ransomware",
        description="Device administrator privileges",
        forensic_note="CRITICAL - Used by ransomware, persistence mechanism",
        abuse_scenario="Lock device for ransomware, prevent uninstall, wipe device"
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionInfo(
        name="REQUEST_INSTALL_PACKAGES",
        risk_level="DANGEROUS",
        risk_score=8,
        category="Malware Dropper",
        description="Install other APK packages",
        forensic_note="Can silently install additional malware components",
        abuse_scenario="Download and install secondary malware payloads"
    ),
    "android.permission.INTERNET": PermissionInfo(
        name="INTERNET",
        risk_level="NORMAL",
        risk_score=2,
        category="Network",
        description="Full internet access",
        forensic_note="Required for data exfiltration to C2 servers",
        abuse_scenario="Exfiltrate data to remote servers"
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": PermissionInfo(
        name="RECEIVE_BOOT_COMPLETED",
        risk_level="DANGEROUS",
        risk_score=6,
        category="Persistence",
        description="Auto-start on device boot",
        forensic_note="Ensures malware persists across reboots",
        abuse_scenario="Maintain persistence, auto-restart after reboot"
    ),
    "android.permission.FOREGROUND_SERVICE": PermissionInfo(
        name="FOREGROUND_SERVICE",
        risk_level="DANGEROUS",
        risk_score=5,
        category="Persistence",
        description="Run persistent foreground service",
        forensic_note="Keeps malware running continuously in background",
        abuse_scenario="Keep C2 connection alive, continuous monitoring"
    ),
    "android.permission.READ_PHONE_STATE": PermissionInfo(
        name="READ_PHONE_STATE",
        risk_level="DANGEROUS",
        risk_score=7,
        category="Device Identity",
        description="Read device identifiers (IMEI, phone number)",
        forensic_note="Collects device fingerprint for tracking",
        abuse_scenario="Collect IMEI, phone number for device fingerprinting"
    ),
    "android.permission.USE_BIOMETRIC": PermissionInfo(
        name="USE_BIOMETRIC",
        risk_level="DANGEROUS",
        risk_score=7,
        category="Authentication Bypass",
        description="Use biometric authentication",
        forensic_note="Can attempt to bypass biometric security",
        abuse_scenario="Intercept biometric authentication flows"
    ),
}

# ─── Dangerous Combinations ──────────────────────────────────
DANGEROUS_COMBINATIONS = [
    {
        "id": "COMBO-001",
        "name": "OTP Banking Fraud Kit",
        "severity": "CRITICAL",
        "permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.SYSTEM_ALERT_WINDOW"
        ],
        "description": "Classic banking trojan combination",
        "forensic_significance": (
            "This permission combination is the hallmark of banking "
            "trojans. The app can display overlay screens over banking "
            "apps to steal credentials while intercepting OTP codes in "
            "real-time and forwarding them to C2 servers."
        )
    },
    {
        "id": "COMBO-002",
        "name": "Silent Surveillance Suite",
        "severity": "CRITICAL",
        "permissions": [
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET"
        ],
        "description": "Complete covert surveillance toolkit",
        "forensic_significance": (
            "This combination enables full covert surveillance including "
            "audio recording, video capture, and real-time location tracking. "
            "Typical of stalkerware or state-sponsored spyware."
        )
    },
    {
        "id": "COMBO-003",
        "name": "Ransomware Persistence Mechanism",
        "severity": "CRITICAL",
        "permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        ],
        "description": "Ransomware infrastructure combination",
        "forensic_significance": (
            "Device admin rights combined with boot persistence and "
            "storage write access indicates ransomware. Can lock device "
            "and encrypt user files."
        )
    },
    {
        "id": "COMBO-004",
        "name": "Data Exfiltration Bundle",
        "severity": "CRITICAL",
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.INTERNET"
        ],
        "description": "Mass personal data theft combination",
        "forensic_significance": (
            "Comprehensive data theft combination targeting contacts, "
            "call history, messages, and files. Typical of commercial "
            "spyware sold to abusers or state actors."
        )
    },
    {
        "id": "COMBO-005",
        "name": "Accessibility-Based Device Takeover",
        "severity": "CRITICAL",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET"
        ],
        "description": "Full device control via accessibility abuse",
        "forensic_significance": (
            "Accessibility service combined with overlay capability "
            "enables complete device takeover. Can perform any action "
            "on behalf of user including banking transactions."
        )
    },
]


class PermissionAnalyzer:
    def __init__(self, permissions: list):
        self.permissions = permissions

    def analyze(self) -> dict:
        categorized = {
            "CRITICAL":  [],
            "DANGEROUS": [],
            "NORMAL":    [],
            "UNKNOWN":   []
        }

        permission_details = []
        total_risk_score   = 0

        for perm in self.permissions:
            if perm in PERMISSION_DATABASE:
                info = PERMISSION_DATABASE[perm]
                categorized[info.risk_level].append(perm)
                total_risk_score += info.risk_score
                permission_details.append({
                    "permission":     perm,
                    "short_name":     info.name,
                    "risk_level":     info.risk_level,
                    "risk_score":     info.risk_score,
                    "category":       info.category,
                    "description":    info.description,
                    "forensic_note":  info.forensic_note,
                    "abuse_scenario": info.abuse_scenario
                })
            else:
                categorized["UNKNOWN"].append(perm)
                permission_details.append({
                    "permission":  perm,
                    "risk_level":  "UNKNOWN",
                    "risk_score":  3,
                    "description": "Third-party or custom permission"
                })

        # Check for dangerous combinations
        found_combos = self._check_combinations()

        # Calculate final risk score
        max_possible    = len(self.permissions) * 10
        risk_percentage = min(
            (total_risk_score / max_possible * 100) if max_possible > 0 else 0,
            100
        )

        return {
            "total_permissions":     len(self.permissions),
            "categorized":           categorized,
            "permission_details":    permission_details,
            "dangerous_combinations":found_combos,
            "risk_score":            total_risk_score,
            "risk_percentage":       round(risk_percentage, 1),
            "risk_grade":            self._calculate_grade(risk_percentage),
            "has_critical_combo":    len(found_combos) > 0,
        }

    def _check_combinations(self) -> list:
        found = []
        perm_set = set(self.permissions)
        for combo in DANGEROUS_COMBINATIONS:
            required = set(combo["permissions"])
            matched  = required.intersection(perm_set)
            if len(matched) >= len(required) * 0.75:  # 75% match threshold
                found.append({
                    **combo,
                    "matched_permissions": list(matched),
                    "missing_permissions": list(required - matched),
                    "match_percentage":    round(len(matched) / len(required) * 100)
                })
        return found

    def _calculate_grade(self, score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "SAFE"
