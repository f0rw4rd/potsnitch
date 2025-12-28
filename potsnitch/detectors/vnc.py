"""VNC honeypot detector.

Detects VNC honeypots including:
- vnclowpot
- QeeqBox VNC
- Custom VNC honeypots

Detection methods:
- PASSIVE: RFB protocol version analysis
- ACTIVE: Password authentication testing, security type probing
"""

import socket
import time
from typing import List, Optional, Tuple

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.probes.credentials import (
    VNC_HONEYPOT_PASSWORDS,
    VNC_INVALID_PAYLOADS,
)
from potsnitch.probes.timing import measure_connection_time


# Known VNC honeypot versions
VNC_HONEYPOT_VERSIONS = [
    b"RFB 003.003",  # Very old, often used in honeypots
    b"RFB 003.007",  # Common in honeypots
]

# Real VNC server identifiers
REAL_VNC_PATTERNS = [
    b"RFB 003.008",  # Modern RFB
    b"RFB 004.",     # Extended RFB
]

# Security types
SECURITY_TYPE_NONE = 1
SECURITY_TYPE_VNC_AUTH = 2
SECURITY_TYPE_TIGHT = 16


@register_detector
class VNCDetector(BaseDetector):
    """Detector for VNC honeypots.

    Static (Passive) Detection:
    - RFB protocol version analysis
    - Security type enumeration

    Dynamic (Active) Detection:
    - Password authentication probing
    - Challenge-response analysis
    - Error handling behavior
    """

    name = "vnc"
    description = "Detects VNC honeypots (vnclowpot, QeeqBox)"
    honeypot_types = ["vnclowpot", "qeeqbox-vnc"]
    default_ports = [5900, 5901, 5902]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive VNC detection.

        Analyzes RFB protocol version and security types.

        Args:
            target: IP address or hostname
            port: VNC port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Get protocol version
        version = self._get_protocol_version(target, port)
        if version:
            self._check_version(version, result)

        # Get security types
        sec_types = self._get_security_types(target, port)
        if sec_types:
            self._check_security_types(sec_types, result)

        # Check connection timing
        timing_result = measure_connection_time(target, port, self.timeout)
        if timing_result.success and timing_result.elapsed < 0.005:
            result.add_indicator(
                Indicator(
                    name="vnc_instant_response",
                    description="VNC handshake completed instantly (< 5ms)",
                    severity=Confidence.LOW,
                    details=f"Response time: {timing_result.elapsed*1000:.2f}ms",
                )
            )

        if result.is_honeypot:
            result.honeypot_type = "vnc_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active VNC probing.

        Tests password authentication and challenge behavior.

        Args:
            target: IP address or hostname
            port: VNC port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Test default passwords
        pwd_indicators = self._probe_passwords(target, port)
        for indicator in pwd_indicators:
            result.add_indicator(indicator)

        # Test accept-all behavior
        accept_all_indicators = self._probe_accept_all(target, port)
        for indicator in accept_all_indicators:
            result.add_indicator(indicator)

        # Test challenge consistency
        challenge_indicators = self._probe_challenge(target, port)
        for indicator in challenge_indicators:
            result.add_indicator(indicator)

        # Test invalid payload responses
        payload_indicators = self._probe_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "vnc_honeypot"

        return result

    def _get_protocol_version(self, target: str, port: int) -> Optional[bytes]:
        """Get RFB protocol version string."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            version = sock.recv(12)  # "RFB xxx.yyy\n"
            sock.close()
            return version
        except (socket.error, socket.timeout, OSError):
            return None

    def _get_security_types(self, target: str, port: int) -> Optional[List[int]]:
        """Get available security types."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server version
            server_version = sock.recv(12)

            # Send client version (same as server)
            sock.send(server_version)

            # Read security types
            # Format: 1 byte count, then N bytes of security types
            count_byte = sock.recv(1)
            if not count_byte:
                sock.close()
                return None

            count = count_byte[0]
            if count == 0:
                # No authentication or error
                sock.close()
                return [0]

            sec_types = sock.recv(count)
            sock.close()

            return list(sec_types)

        except (socket.error, socket.timeout, OSError):
            return None

    def _check_version(self, version: bytes, result: DetectionResult) -> None:
        """Check protocol version for honeypot signatures."""
        for hp_version in VNC_HONEYPOT_VERSIONS:
            if hp_version in version:
                result.add_indicator(
                    Indicator(
                        name="vnc_old_protocol",
                        description=f"Old RFB protocol version: {version.decode('utf-8', errors='ignore').strip()}",
                        severity=Confidence.LOW,
                        details="Old protocol versions are common in honeypots",
                    )
                )
                return

    def _check_security_types(self, sec_types: List[int], result: DetectionResult) -> None:
        """Check security types for honeypot indicators."""
        # No authentication = suspicious
        if SECURITY_TYPE_NONE in sec_types and len(sec_types) == 1:
            result.add_indicator(
                Indicator(
                    name="vnc_no_auth",
                    description="VNC requires no authentication",
                    severity=Confidence.HIGH,
                    details="Open VNC servers are rare; could be honeypot",
                )
            )

        # Only VNC auth with no other options
        if sec_types == [SECURITY_TYPE_VNC_AUTH]:
            result.add_indicator(
                Indicator(
                    name="vnc_basic_auth_only",
                    description="Only basic VNC authentication supported",
                    severity=Confidence.LOW,
                    details="Modern VNC servers support multiple auth types",
                )
            )

    def _probe_passwords(self, target: str, port: int) -> List[Indicator]:
        """Test VNC with default passwords."""
        indicators = []

        for password in VNC_HONEYPOT_PASSWORDS[:5]:
            success, timing = self._try_auth(target, port, password)

            if success:
                indicators.append(
                    Indicator(
                        name="vnc_default_password_accepted",
                        description=f"Default password '{password or '(empty)'}' accepted",
                        severity=Confidence.HIGH,
                        details="VNC honeypots often accept default passwords",
                    )
                )
                break

            # Check for suspiciously fast rejection
            if timing > 0 and timing < 0.01:
                indicators.append(
                    Indicator(
                        name="vnc_instant_auth_rejection",
                        description="Authentication rejected instantly (< 10ms)",
                        severity=Confidence.LOW,
                        details=f"Response time: {timing*1000:.2f}ms",
                    )
                )

        return indicators

    def _probe_accept_all(self, target: str, port: int) -> List[Indicator]:
        """Test if VNC accepts any password."""
        indicators = []

        # Try random garbage passwords
        garbage_passwords = [
            "xK7#mQ2$nLpR",
            "9Yx!mN4@wRtP",
            "\x00\x00\x00\x00",
        ]

        for password in garbage_passwords:
            success, _ = self._try_auth(target, port, password)
            if success:
                indicators.append(
                    Indicator(
                        name="vnc_accept_all",
                        description="VNC accepts garbage/random passwords",
                        severity=Confidence.DEFINITE,
                        details=f"Accepted password: {repr(password)}",
                    )
                )
                return indicators

        return indicators

    def _try_auth(self, target: str, port: int, password: str) -> Tuple[bool, float]:
        """Attempt VNC authentication.

        Returns:
            Tuple of (success, elapsed_time)
        """
        try:
            import hashlib

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server version
            server_version = sock.recv(12)

            # Send client version
            sock.send(server_version)

            # Read security types
            count_byte = sock.recv(1)
            if not count_byte:
                sock.close()
                return False, 0

            count = count_byte[0]
            if count == 0:
                sock.close()
                return False, 0

            sec_types = sock.recv(count)

            # Choose VNC auth if available
            if SECURITY_TYPE_VNC_AUTH not in sec_types:
                # No password auth, check for no-auth
                if SECURITY_TYPE_NONE in sec_types:
                    sock.send(bytes([SECURITY_TYPE_NONE]))
                    result = sock.recv(4)
                    sock.close()
                    return result == b"\x00\x00\x00\x00", 0
                sock.close()
                return False, 0

            # Request VNC auth
            sock.send(bytes([SECURITY_TYPE_VNC_AUTH]))

            # Get challenge
            start = time.perf_counter()
            challenge = sock.recv(16)

            if len(challenge) != 16:
                sock.close()
                return False, 0

            # Encrypt challenge with password using DES
            # VNC uses a specific key format (reversed bits in each byte)
            try:
                from Crypto.Cipher import DES

                # Prepare password (pad/truncate to 8 bytes)
                key = password.encode()[:8].ljust(8, b'\x00')

                # Reverse bits in each byte (VNC specific)
                def reverse_bits(byte):
                    return int('{:08b}'.format(byte)[::-1], 2)

                key = bytes(reverse_bits(b) for b in key)

                cipher = DES.new(key, DES.MODE_ECB)
                response = cipher.encrypt(challenge)

                sock.send(response)
            except ImportError:
                # No pycryptodome, send garbage response
                sock.send(b"\x00" * 16)

            # Read result
            result = sock.recv(4)
            elapsed = time.perf_counter() - start

            sock.close()

            # 0 = success, non-0 = failure
            success = result == b"\x00\x00\x00\x00"
            return success, elapsed

        except (socket.error, socket.timeout, OSError):
            return False, 0

    def _probe_challenge(self, target: str, port: int) -> List[Indicator]:
        """Check if VNC challenge is static (honeypot indicator)."""
        indicators = []
        challenges = []

        for _ in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                server_version = sock.recv(12)
                sock.send(server_version)

                count = sock.recv(1)[0]
                sec_types = sock.recv(count)

                if SECURITY_TYPE_VNC_AUTH in sec_types:
                    sock.send(bytes([SECURITY_TYPE_VNC_AUTH]))
                    challenge = sock.recv(16)
                    challenges.append(challenge)

                sock.close()
                time.sleep(0.1)

            except (socket.error, socket.timeout, OSError):
                continue

        # Check if challenges are static
        if len(challenges) >= 2 and len(set(challenges)) == 1:
            indicators.append(
                Indicator(
                    name="vnc_static_challenge",
                    description="VNC challenge is static (not random)",
                    severity=Confidence.DEFINITE,
                    details="Real VNC servers generate random challenges",
                )
            )

        return indicators

    def _probe_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test VNC response to invalid payloads."""
        indicators = []
        responses = []

        for payload in VNC_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Send invalid payload instead of proper handshake
                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        if len(responses) >= 2:
            unique = set(responses)
            if len(unique) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="vnc_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                    )
                )

        return indicators

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for VNC honeypot hardening."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "vnc_static_challenge":
                recommendations.append(
                    "Generate random challenges for each authentication attempt"
                )
            elif indicator.name == "vnc_accept_all":
                recommendations.append(
                    "Implement proper password validation"
                )
            elif indicator.name == "vnc_old_protocol":
                recommendations.append(
                    "Use modern RFB protocol version (3.8+)"
                )

        return recommendations
