"""SMTP honeypot detector.

Detects SMTP/mail honeypots including:
- Mailoney
- Heralding SMTP
- Shiva spam honeypot
- QeeqBox SMTP

Detection methods:
- PASSIVE: Banner analysis, greeting patterns
- ACTIVE: EHLO/HELO fingerprinting, VRFY probing, open relay testing
"""

import socket
import time
from typing import List, Optional, Tuple

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.probes.credentials import (
    SMTP_HONEYPOT_CREDENTIALS,
    SMTP_INVALID_PAYLOADS,
    GARBAGE_CREDENTIALS,
)
from potsnitch.probes.timing import measure_connection_time


# Known SMTP honeypot banners
SMTP_HONEYPOT_BANNERS = [
    b"220 mail.example.com",           # Mailoney default
    b"220 Microsoft ESMTP MAIL",       # Heralding
    b"220 mail.honeypot.local",        # Common default
    b"220 qeeqbox",                    # QeeqBox
    b"220 SMTP Honeypot",              # Generic
]

# Default hostnames that indicate honeypots
HONEYPOT_HOSTNAMES = [
    "mail.example.com",
    "mail.honeypot.local",
    "localhost",
    "example.com",
    "mail.test.local",
]

# SMTP commands to probe
SMTP_PROBE_COMMANDS = [
    b"VRFY admin\r\n",      # Verify user
    b"EXPN admin\r\n",      # Expand mailing list
    b"HELP\r\n",            # Help
    b"NOOP\r\n",            # No-op
]


@register_detector
class SMTPDetector(BaseDetector):
    """Detector for SMTP honeypots.

    Static (Passive) Detection:
    - Banner/greeting analysis
    - Default hostname detection

    Dynamic (Active) Detection:
    - EHLO/HELO response fingerprinting
    - VRFY/EXPN command behavior
    - Open relay detection
    - AUTH mechanism probing
    - Credential testing
    """

    name = "smtp"
    description = "Detects SMTP honeypots (Mailoney, Heralding)"
    honeypot_types = ["mailoney", "heralding-smtp", "shiva", "qeeqbox-smtp"]
    default_ports = [25, 587, 465, 2525]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive SMTP detection.

        Connects and analyzes banner without sending commands.

        Args:
            target: IP address or hostname
            port: SMTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Get banner and analyze
        banner = self._get_banner(target, port)
        if banner:
            self._check_banner(banner, result)

        # Check connection timing
        timing_result = measure_connection_time(target, port, self.timeout)
        if timing_result.success and timing_result.elapsed < 0.005:
            result.add_indicator(
                Indicator(
                    name="smtp_instant_banner",
                    description="SMTP banner returned instantly (< 5ms)",
                    severity=Confidence.LOW,
                    details=f"Response time: {timing_result.elapsed*1000:.2f}ms",
                )
            )

        if result.is_honeypot:
            result.honeypot_type = "smtp_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active SMTP probing.

        Tests EHLO, VRFY, AUTH, and relay behavior.

        Args:
            target: IP address or hostname
            port: SMTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Test EHLO response
        ehlo_indicators = self._probe_ehlo(target, port)
        for indicator in ehlo_indicators:
            result.add_indicator(indicator)

        # Test VRFY/EXPN commands
        vrfy_indicators = self._probe_vrfy(target, port)
        for indicator in vrfy_indicators:
            result.add_indicator(indicator)

        # Test open relay behavior
        relay_indicators = self._probe_open_relay(target, port)
        for indicator in relay_indicators:
            result.add_indicator(indicator)

        # Test AUTH with credentials
        auth_indicators = self._probe_auth(target, port)
        for indicator in auth_indicators:
            result.add_indicator(indicator)

        # Test invalid payload responses
        payload_indicators = self._probe_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "smtp_honeypot"

        return result

    def _get_banner(self, target: str, port: int) -> Optional[bytes]:
        """Get SMTP banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)
            sock.close()
            return banner
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_banner(self, banner: bytes, result: DetectionResult) -> None:
        """Check banner for honeypot signatures."""
        banner_lower = banner.lower()
        banner_str = banner.decode("utf-8", errors="ignore")

        for hp_banner in SMTP_HONEYPOT_BANNERS:
            if hp_banner.lower() in banner_lower:
                result.add_indicator(
                    Indicator(
                        name="smtp_honeypot_banner",
                        description="Known SMTP honeypot banner detected",
                        severity=Confidence.HIGH,
                        details=banner_str[:100],
                    )
                )
                return

        # Check for default hostnames
        for hostname in HONEYPOT_HOSTNAMES:
            if hostname in banner_str:
                result.add_indicator(
                    Indicator(
                        name="smtp_default_hostname",
                        description=f"Default/example hostname in banner: {hostname}",
                        severity=Confidence.MEDIUM,
                        details="Real mail servers use proper hostnames",
                    )
                )
                break

        # Check for mailoney signature
        if b"mailoney" in banner_lower:
            result.add_indicator(
                Indicator(
                    name="smtp_mailoney_signature",
                    description="Mailoney signature in banner",
                    severity=Confidence.DEFINITE,
                )
            )

    def _probe_ehlo(self, target: str, port: int) -> List[Indicator]:
        """Test EHLO response for honeypot indicators."""
        indicators = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read banner
            sock.recv(1024)

            # Send EHLO
            sock.send(b"EHLO test.example.com\r\n")
            ehlo_response = sock.recv(4096)

            sock.close()

            response_str = ehlo_response.decode("utf-8", errors="ignore").lower()

            # Check for limited capabilities
            extensions = ["auth", "starttls", "size", "pipelining", "8bitmime"]
            missing = [ext for ext in extensions if ext not in response_str]

            if len(missing) >= 4:  # Missing most extensions
                indicators.append(
                    Indicator(
                        name="smtp_limited_extensions",
                        description=f"SMTP server missing common extensions: {', '.join(missing)}",
                        severity=Confidence.MEDIUM,
                        details="Honeypots often implement minimal SMTP",
                    )
                )

            # Check for only LOGIN/PLAIN auth (common in honeypots)
            if b"auth" in ehlo_response.lower():
                if b"login" in ehlo_response.lower() and b"cram-md5" not in ehlo_response.lower():
                    indicators.append(
                        Indicator(
                            name="smtp_weak_auth_only",
                            description="Only weak AUTH mechanisms (LOGIN/PLAIN)",
                            severity=Confidence.LOW,
                            details="Real servers often support CRAM-MD5",
                        )
                    )

        except (socket.error, socket.timeout, OSError):
            pass

        return indicators

    def _probe_vrfy(self, target: str, port: int) -> List[Indicator]:
        """Test VRFY command behavior."""
        indicators = []
        responses = []

        test_users = [
            b"VRFY admin\r\n",
            b"VRFY root\r\n",
            b"VRFY nonexistent_user_xyz\r\n",
            b"VRFY ${jndi:ldap://x}\r\n",  # Log4j attempt
        ]

        for cmd in test_users:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.recv(1024)  # Banner
                sock.send(cmd)
                response = sock.recv(1024)
                responses.append(response)
                sock.close()
            except (socket.error, socket.timeout, OSError):
                continue

        if len(responses) >= 3:
            # Check for uniform responses
            if len(set(responses)) == 1:
                indicators.append(
                    Indicator(
                        name="smtp_vrfy_uniform",
                        description="VRFY returns identical response for all users",
                        severity=Confidence.MEDIUM,
                        details="Real servers differentiate between valid/invalid users",
                    )
                )

            # Check if all users are "valid" (honeypot behavior)
            valid_count = sum(1 for r in responses if b"250" in r or b"252" in r)
            if valid_count == len(responses):
                indicators.append(
                    Indicator(
                        name="smtp_vrfy_accept_all",
                        description="VRFY accepts all users including fake ones",
                        severity=Confidence.HIGH,
                        details="Honeypots often accept any username",
                    )
                )

        return indicators

    def _probe_open_relay(self, target: str, port: int) -> List[Indicator]:
        """Test for open relay behavior."""
        indicators = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read banner
            sock.recv(1024)

            # EHLO
            sock.send(b"EHLO test.example.com\r\n")
            sock.recv(1024)

            # Try to relay (should be rejected by real servers)
            sock.send(b"MAIL FROM:<attacker@evil.com>\r\n")
            mail_response = sock.recv(1024)

            sock.send(b"RCPT TO:<victim@external.com>\r\n")
            rcpt_response = sock.recv(1024)

            sock.close()

            # Check if both were accepted (open relay = honeypot behavior)
            if b"250" in mail_response and b"250" in rcpt_response:
                indicators.append(
                    Indicator(
                        name="smtp_open_relay",
                        description="SMTP server appears to be an open relay",
                        severity=Confidence.DEFINITE,
                        details="Honeypots often act as open relays to capture spam",
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

        return indicators

    def _probe_auth(self, target: str, port: int) -> List[Indicator]:
        """Test SMTP AUTH with credentials."""
        indicators = []

        # Test default credentials
        for username, password in SMTP_HONEYPOT_CREDENTIALS[:3]:
            success = self._try_auth(target, port, username, password)
            if success:
                indicators.append(
                    Indicator(
                        name="smtp_default_cred_accepted",
                        description=f"Default credential {username}:{password} accepted",
                        severity=Confidence.HIGH,
                    )
                )
                break

        # Test garbage credentials
        for username, password in GARBAGE_CREDENTIALS[:2]:
            success = self._try_auth(target, port, username, password)
            if success:
                indicators.append(
                    Indicator(
                        name="smtp_accept_all_auth",
                        description="SMTP accepts garbage credentials",
                        severity=Confidence.DEFINITE,
                        details=f"Accepted: {username}:{password}",
                    )
                )
                break

        return indicators

    def _try_auth(self, target: str, port: int, username: str, password: str) -> bool:
        """Attempt SMTP AUTH LOGIN."""
        try:
            import base64

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            sock.recv(1024)  # Banner
            sock.send(b"EHLO test.example.com\r\n")
            sock.recv(1024)

            # AUTH LOGIN
            sock.send(b"AUTH LOGIN\r\n")
            response = sock.recv(1024)

            if b"334" not in response:
                sock.close()
                return False

            # Send username
            sock.send(base64.b64encode(username.encode()) + b"\r\n")
            response = sock.recv(1024)

            if b"334" not in response:
                sock.close()
                return False

            # Send password
            sock.send(base64.b64encode(password.encode()) + b"\r\n")
            response = sock.recv(1024)

            sock.close()

            # Check for success (235)
            return b"235" in response

        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test SMTP response to invalid payloads."""
        indicators = []
        responses = []

        for payload in SMTP_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.recv(1024)  # Banner
                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        if len(responses) >= 3:
            unique = set(responses)
            if len(unique) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="smtp_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                    )
                )

        return indicators

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for SMTP honeypot hardening."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "smtp_default_hostname":
                recommendations.append(
                    "Configure a proper hostname instead of example.com"
                )
            elif indicator.name == "smtp_open_relay":
                recommendations.append(
                    "Implement relay restrictions to avoid trivial detection"
                )
            elif indicator.name == "smtp_accept_all_auth":
                recommendations.append(
                    "Implement proper credential validation"
                )
            elif indicator.name == "smtp_limited_extensions":
                recommendations.append(
                    "Implement more SMTP extensions (STARTTLS, SIZE, etc.)"
                )

        return recommendations
