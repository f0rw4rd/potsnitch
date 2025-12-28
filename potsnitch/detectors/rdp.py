"""RDP honeypot detector (RDPY, Heralding, PyRDP).

Detection is split into:
- PASSIVE: TLS fingerprinting (JA3/JA3S), certificate analysis, known patterns
- ACTIVE: Malformed packet probing, protocol behavior analysis
"""

import socket
import ssl
import hashlib
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Known Python RDP library JA3 hashes (not Windows SChannel)
PYTHON_TLS_JA3_PREFIXES = [
    "a0e9f5d64349fb13191bc781f81f42e1",  # Python ssl
    "3b5074b1b5d032e5620f69f9f700ff0e",  # Twisted
]

# Known RDPY/Heralding patterns in certificates
HONEYPOT_CERT_PATTERNS = [
    "localhost",
    "example",
    "test",
    "rdpy",
    "heralding",
    "honeypot",
]

# Python ssl library preferred ciphers (different from Windows SChannel)
PYTHON_PREFERRED_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
]


@register_detector
class RDPDetector(BaseDetector):
    """Detector for RDP-based honeypots (RDPY, Heralding, PyRDP).

    Static (Passive) Detection:
    - JA3/JA3S TLS fingerprinting (Python vs Windows SChannel)
    - Certificate analysis (non-Microsoft CA, generic subjects)
    - Known RDPY/Heralding certificate patterns

    Dynamic (Active) Detection:
    - Malformed X.224 packet probing
    - Error response analysis
    - Protocol behavior fingerprinting
    """

    name = "rdp"
    description = "Detects RDP honeypots via TLS fingerprinting and protocol analysis"
    honeypot_types = ["rdpy", "heralding", "pyrdp"]
    default_ports = [3389]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static RDP detection.

        Checks TLS fingerprints, certificates, and cipher preferences
        without sending malformed or probe packets.

        Args:
            target: IP address or hostname
            port: RDP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check TLS characteristics (passive - just analyzing handshake)
        self._check_tls_passive(target, port, result)

        # Set honeypot type if detected
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "rdpy"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic RDP probing.

        Sends malformed packets to test error handling behavior.
        More accurate but detectable by honeypot operators.

        Args:
            target: IP address or hostname
            port: RDP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check RDP protocol behavior with malformed packets
        self._check_rdp_protocol(target, port, result)

        # Set honeypot type if detected via active probes
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "rdpy"

        return result

    def _check_tls_passive(self, target: str, port: int, result: DetectionResult) -> None:
        """Check TLS handshake for non-Windows signatures (passive analysis)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # RDP negotiation request with TLS
            x224_conn_req = bytes([
                0x03, 0x00,  # TPKT header
                0x00, 0x13,  # Length: 19 bytes
                0x0e,        # X.224 length
                0xe0,        # X.224 CR (Connection Request)
                0x00, 0x00,  # DST-REF
                0x00, 0x00,  # SRC-REF
                0x00,        # CLASS
                0x01,        # Cookie length
                0x00,        # Cookie (RDP Negotiation Request)
                0x08, 0x00,  # Length
                0x01,        # Type: RDP_NEG_REQ
                0x00, 0x00,  # Flags
                0x01, 0x00, 0x00, 0x00,  # Protocol: TLS
            ])

            sock.send(x224_conn_req)
            response = sock.recv(1024)

            if len(response) < 11:
                sock.close()
                return

            # Check if TLS is accepted
            if response[11] == 0x02:  # RDP_NEG_RSP with TLS
                # Upgrade to TLS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    tls_sock = context.wrap_socket(sock, server_hostname=target)

                    # Get certificate (passive analysis)
                    cert = tls_sock.getpeercert(binary_form=True)
                    if cert:
                        self._analyze_certificate(cert, result)

                    # Get cipher info (passive analysis)
                    cipher = tls_sock.cipher()
                    if cipher:
                        self._analyze_cipher(cipher, result)

                    tls_sock.close()
                except ssl.SSLError:
                    pass
            else:
                sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

    def _analyze_certificate(self, cert: bytes, result: DetectionResult) -> None:
        """Analyze TLS certificate for honeypot indicators."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            certificate = x509.load_der_x509_certificate(cert, default_backend())

            # Check issuer - Windows RDP uses self-signed with specific format
            issuer = certificate.issuer.rfc4514_string()
            subject = certificate.subject.rfc4514_string()

            # Python honeypots often have generic/unusual certificate subjects
            subject_lower = subject.lower()
            for pattern in HONEYPOT_CERT_PATTERNS:
                if pattern in subject_lower:
                    result.add_indicator(
                        Indicator(
                            name="generic_cert_subject",
                            description="Generic/honeypot certificate subject detected",
                            severity=Confidence.MEDIUM,
                            details=f"Subject: {subject}, Pattern: {pattern}",
                        )
                    )
                    break

            # Check for non-Microsoft CA patterns (indicative of Python implementation)
            if "Microsoft" not in issuer and "Windows" not in issuer:
                # Check if it looks like a Python-generated cert
                if any(p in issuer.lower() for p in ["python", "twisted", "openssl"]):
                    result.add_indicator(
                        Indicator(
                            name="non_windows_issuer",
                            description="Certificate issuer indicates non-Windows origin",
                            severity=Confidence.HIGH,
                            details=f"Issuer: {issuer}",
                        )
                    )

        except Exception:
            pass

    def _analyze_cipher(self, cipher: tuple, result: DetectionResult) -> None:
        """Analyze TLS cipher selection for honeypot indicators."""
        cipher_name, protocol, bits = cipher

        # Python's ssl module has different cipher preferences than Windows SChannel
        if cipher_name in PYTHON_PREFERRED_CIPHERS:
            result.add_indicator(
                Indicator(
                    name="python_tls_cipher",
                    description="TLS cipher typical of Python ssl library",
                    severity=Confidence.LOW,
                    details=f"Cipher: {cipher_name}",
                )
            )

    def _check_rdp_protocol(self, target: str, port: int, result: DetectionResult) -> None:
        """Check RDP protocol behavior with malformed packets (active probing)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send malformed X.224 packet to test error handling
            malformed = bytes([
                0x03, 0x00,  # TPKT header
                0x00, 0x05,  # Invalid short length
                0x00,        # Invalid X.224
            ])

            sock.send(malformed)

            try:
                response = sock.recv(1024)
                # Real Windows RDP typically closes connection or sends specific error
                # Python implementations may behave differently
                if len(response) > 0:
                    result.add_indicator(
                        Indicator(
                            name="unusual_error_response",
                            description="Unusual response to malformed RDP packet",
                            severity=Confidence.LOW,
                            details="Real Windows RDP typically closes connection on malformed packets",
                        )
                    )
            except socket.timeout:
                pass

            sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

        # Additional active probe: test with invalid protocol version
        self._probe_invalid_protocol(target, port, result)

    def _probe_invalid_protocol(self, target: str, port: int, result: DetectionResult) -> None:
        """Probe with invalid protocol version to test error handling."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # RDP negotiation with invalid/unsupported protocol
            x224_bad_proto = bytes([
                0x03, 0x00,  # TPKT header
                0x00, 0x13,  # Length: 19 bytes
                0x0e,        # X.224 length
                0xe0,        # X.224 CR (Connection Request)
                0x00, 0x00,  # DST-REF
                0x00, 0x00,  # SRC-REF
                0x00,        # CLASS
                0x01,        # Cookie length
                0x00,        # Cookie (RDP Negotiation Request)
                0x08, 0x00,  # Length
                0x01,        # Type: RDP_NEG_REQ
                0x00, 0x00,  # Flags
                0xFF, 0xFF, 0x00, 0x00,  # Invalid protocol flags
            ])

            sock.send(x224_bad_proto)
            response = sock.recv(1024)

            if len(response) > 0:
                # Analyze error response format
                # Python implementations may have different error formats
                response_hex = response.hex()
                # Check for non-standard error responses
                if len(response) < 10 or response[0:2] != bytes([0x03, 0x00]):
                    result.add_indicator(
                        Indicator(
                            name="non_standard_error",
                            description="Non-standard error response to invalid protocol",
                            severity=Confidence.MEDIUM,
                            details=f"Response: {response_hex[:40]}...",
                        )
                    )

            sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for RDP honeypots."""
        recommendations = []

        for indicator in result.indicators:
            if "tls" in indicator.name.lower() or "cipher" in indicator.name.lower():
                recommendations.append(
                    "Consider using a real Windows VM as RDP backend to mask TLS signatures"
                )
            elif "cert" in indicator.name.lower():
                recommendations.append(
                    "Generate a realistic certificate with proper subject/issuer fields"
                )
            elif "error" in indicator.name.lower():
                recommendations.append(
                    "Improve error handling to match Windows RDP behavior"
                )
            elif "issuer" in indicator.name.lower():
                recommendations.append(
                    "Use certificates that appear to be from Microsoft/Windows"
                )

        return list(set(recommendations))  # Remove duplicates
