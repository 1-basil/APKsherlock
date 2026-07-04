# backend/analyzer/static/certificate_analyzer.py

from androguard.core.apk import APK
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import hashlib

class CertificateAnalyzer:
    """
    Analyzes APK signing certificate for developer identity
    Critical for law enforcement attribution
    """

    def __init__(self, apk: APK):
        self.apk = apk

    def analyze(self) -> dict:
        try:
            # Get certificate bytes from APK
            certs = self.apk.get_certificates_der_v2()
            if not certs:
                certs = [self.apk.get_certificate_der(0)]

            cert_analyses = []
            for cert_der in certs:
                cert_analyses.append(self._analyze_cert(cert_der))

            return {
                "certificates":       cert_analyses,
                "is_debug_signed":    self._is_debug_cert(cert_analyses),
                "is_self_signed":     self._is_self_signed(cert_analyses),
                "signing_scheme":     self._get_signing_scheme(),
                "forensic_summary":   self._build_forensic_summary(cert_analyses),
                "attribution_clues":  self._extract_attribution(cert_analyses),
            }
        except Exception as e:
            return {"error": str(e), "certificates": []}

    def _analyze_cert(self, cert_der: bytes) -> dict:
        """Parse and analyze a single X.509 certificate"""
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Compute hashes for forensic identification
        cert_hash_md5    = hashlib.md5(cert_der).hexdigest()
        cert_hash_sha1   = hashlib.sha1(cert_der).hexdigest()
        cert_hash_sha256 = hashlib.sha256(cert_der).hexdigest()

        # Extract subject information (developer identity)
        subject_info = self._parse_name(cert.subject)
        issuer_info  = self._parse_name(cert.issuer)

        # Check expiry
        now      = datetime.datetime.utcnow()
        is_valid = cert.not_valid_before <= now <= cert.not_valid_after

        return {
            "subject": subject_info,
            "issuer":  issuer_info,
            "validity": {
                "not_before": cert.not_valid_before.isoformat(),
                "not_after":  cert.not_valid_after.isoformat(),
                "is_valid":   is_valid,
                "days_until_expiry": (cert.not_valid_after - now).days
            },
            "serial_number":    str(cert.serial_number),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "hashes": {
                "md5":    cert_hash_md5,
                "sha1":   cert_hash_sha1,
                "sha256": cert_hash_sha256,
            },
            "public_key_size": cert.public_key().key_size,
            "version":         cert.version.name,
        }

    def _parse_name(self, name) -> dict:
        """Parse X.509 distinguished name"""
        result = {}
        field_map = {
            "commonName":             "common_name",
            "organizationName":       "organization",
            "organizationalUnitName": "org_unit",
            "countryName":            "country",
            "stateOrProvinceName":    "state",
            "localityName":           "locality",
            "emailAddress":           "email",
        }
        for attr in name:
            field = field_map.get(attr.oid._name, attr.oid._name)
            result[field] = attr.value
        return result

    def _is_debug_cert(self, certs: list) -> bool:
        """Check if signed with Android debug key"""
        for cert in certs:
            subject = cert.get("subject", {})
            if (subject.get("common_name") == "Android Debug" or
                subject.get("organization") == "Android"):
                return True
        return False

    def _is_self_signed(self, certs: list) -> bool:
        """Check if self-signed (subject == issuer)"""
        for cert in certs:
            if cert.get("subject") == cert.get("issuer"):
                return True
        return False

    def _get_signing_scheme(self) -> str:
        """Determine APK signing scheme version"""
        # Determine signing scheme based on androguard features
        if hasattr(self.apk, 'is_signed_v3') and self.apk.is_signed_v3():
            return "v3"
        elif hasattr(self.apk, 'is_signed_v2') and self.apk.is_signed_v2():
            return "v2"
        elif hasattr(self.apk, 'is_signed_v1') and self.apk.is_signed_v1():
            return "v1"
        return "unknown"

    def _build_forensic_summary(self, cert_analyses: list) -> str:
        """Build a forensic summary based on the certificates"""
        if self._is_debug_cert(cert_analyses):
            return "App is signed with a generic Android debug certificate. Developer attribution is limited."
        elif self._is_self_signed(cert_analyses):
            return "App uses a self-signed certificate. Examine the subject and issuer fields for possible clues."
        else:
            return "App uses a custom certificate. Check validity and developer details."
    def _extract_attribution(self, cert_analyses: list) -> list:
        """Extract possible clues for developer attribution"""
        clues = []
        for cert in cert_analyses:
            subject = cert.get("subject", {})
            for key, val in subject.items():
                if val:
                    clues.append(f"{key}: {val}")
                    # Heuristic for packer randomized certs (e.g. 7ZA6JD)
                    if key in ("common_name", "organization") and len(val) == 6 and val.isalnum() and val.isupper():
                        clues.append(f"⚠️ HIGH RISK: {key} '{val}' appears to be a randomized string often used by Chinese packers (NP Manager/NagaPak).")
        return clues
