"""FTP honeypot detector.

Detects FTP honeypots including:
- Dionaea FTP service
- QeeqBox FTP honeypot
- Custom FTP honeypots

Detection methods:
- PASSIVE: Banner analysis, port detection
- ACTIVE: Credential testing, command support, timing analysis
"""

import socket
import time
from typing import List, Optional, Tuple

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.probes.credentials import (
    FTP_HONEYPOT_CREDENTIALS,
    FTP_INVALID_PAYLOADS,
    GARBAGE_CREDENTIALS,
)
from potsnitch.probes.timing import (
    TimingProbe,
    measure_connection_time,
    analyze_timing_samples,
)


# Known FTP honeypot banners
FTP_HONEYPOT_BANNERS = [
    b"220 DiskStation FTP server ready",  # Dionaea default
    b"220 Dionaea",                        # Dionaea signature
    b"220 Welcome to FTP server",          # Generic honeypot
    b"220 FTP Server Ready",               # Generic
    b"220 qeeqbox",                        # QeeqBox
]

# Commands that honeypots often don't implement properly
FTP_PROBE_COMMANDS = [
    b"SYST\r\n",      # System type
    b"FEAT\r\n",      # Feature list
    b"STAT\r\n",      # Server status
    b"HELP\r\n",      # Help
    b"SITE HELP\r\n", # Site-specific help
]


@register_detector
class FTPDetector(BaseDetector):
    """Detector for FTP honeypots.

    Static (Passive) Detection:
    - Banner analysis for known honeypot signatures
    - Response timing on connect

    Dynamic (Active) Detection:
    - Credential testing with default passwords
    - Accept-all detection with garbage credentials
    - Command support analysis
    - Error message uniformity
    """

    name = "ftp"
    description = "Detects FTP honeypots (Dionaea, QeeqBox)"
    honeypot_types = ["dionaea-ftp", "qeeqbox-ftp"]
    default_ports = [21, 2121]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive FTP detection.

        Connects and analyzes banner without sending commands.

        Args:
            target: IP address or hostname
            port: FTP port

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
                    name="ftp_instant_banner",
                    description="FTP banner returned instantly (< 5ms)",
                    severity=Confidence.LOW,
                    details=f"Response time: {timing_result.elapsed*1000:.2f}ms",
                )
            )

        if result.is_honeypot:
            result.honeypot_type = "ftp_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active FTP probing.

        Tests credentials, command support, and error handling.

        Args:
            target: IP address or hostname
            port: FTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Test default credentials and run post-login probes if successful
        cred_indicators, auth_creds = self._probe_credentials_with_postlogin(target, port)
        for indicator in cred_indicators:
            result.add_indicator(indicator)

        # Test accept-all behavior with garbage credentials
        if not auth_creds:
            garbage_indicators, auth_creds = self._probe_accept_all_with_postlogin(target, port)
            for indicator in garbage_indicators:
                result.add_indicator(indicator)

        # Test command support
        cmd_indicators = self._probe_commands(target, port)
        for indicator in cmd_indicators:
            result.add_indicator(indicator)

        # Test invalid payload responses
        payload_indicators = self._probe_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "ftp_honeypot"

        return result

    def _get_banner(self, target: str, port: int) -> Optional[bytes]:
        """Get FTP banner."""
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

        for hp_banner in FTP_HONEYPOT_BANNERS:
            if hp_banner.lower() in banner_lower:
                result.add_indicator(
                    Indicator(
                        name="ftp_honeypot_banner",
                        description="Known FTP honeypot banner detected",
                        severity=Confidence.HIGH,
                        details=banner[:100].decode("utf-8", errors="ignore"),
                    )
                )
                return

        # Check for suspicious patterns
        if b"dionaea" in banner_lower:
            result.add_indicator(
                Indicator(
                    name="ftp_dionaea_signature",
                    description="Dionaea signature in FTP banner",
                    severity=Confidence.DEFINITE,
                )
            )

    def _probe_credentials(self, target: str, port: int) -> List[Indicator]:
        """Test FTP with default credentials."""
        indicators = []

        for username, password in FTP_HONEYPOT_CREDENTIALS[:5]:
            success, timing = self._try_login(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="ftp_default_cred_accepted",
                        description=f"Default credential {username}:{password or '(empty)'} accepted",
                        severity=Confidence.HIGH,
                        details="FTP honeypots often accept default credentials",
                    )
                )
                break

        return indicators

    def _probe_accept_all(self, target: str, port: int) -> List[Indicator]:
        """Test if FTP accepts garbage credentials (accept-all detection)."""
        indicators = []

        for username, password in GARBAGE_CREDENTIALS[:3]:
            success, _ = self._try_login(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="ftp_accept_all",
                        description="FTP accepts garbage/random credentials",
                        severity=Confidence.DEFINITE,
                        details=f"Accepted: {username}:{password}",
                    )
                )
                return indicators  # One is enough

        return indicators

    def _probe_credentials_with_postlogin(
        self, target: str, port: int
    ) -> Tuple[List[Indicator], Optional[Tuple[str, str]]]:
        """Test FTP with default credentials and run post-login probes if successful.

        Args:
            target: Target host
            port: FTP port

        Returns:
            Tuple of (indicators, successful_credentials or None)
        """
        indicators = []
        successful_creds = None

        for username, password in FTP_HONEYPOT_CREDENTIALS[:5]:
            success, timing = self._try_login(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="ftp_default_cred_accepted",
                        description=f"Default credential {username}:{password or '(empty)'} accepted",
                        severity=Confidence.HIGH,
                        details="FTP honeypots often accept default credentials",
                    )
                )
                successful_creds = (username, password)

                # Run post-login probes
                post_login_indicators = self._probe_ftp_post_login(
                    target, port, username, password
                )
                indicators.extend(post_login_indicators)
                break

        return indicators, successful_creds

    def _probe_accept_all_with_postlogin(
        self, target: str, port: int
    ) -> Tuple[List[Indicator], Optional[Tuple[str, str]]]:
        """Test if FTP accepts garbage credentials and run post-login probes.

        Args:
            target: Target host
            port: FTP port

        Returns:
            Tuple of (indicators, successful_credentials or None)
        """
        indicators = []
        successful_creds = None

        for username, password in GARBAGE_CREDENTIALS[:3]:
            success, _ = self._try_login(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="ftp_accept_all",
                        description="FTP accepts garbage/random credentials",
                        severity=Confidence.DEFINITE,
                        details=f"Accepted: {username}:{password}",
                    )
                )
                successful_creds = (username, password)

                # Run post-login probes
                post_login_indicators = self._probe_ftp_post_login(
                    target, port, username, password
                )
                indicators.extend(post_login_indicators)
                return indicators, successful_creds

        return indicators, successful_creds

    def _probe_ftp_post_login(
        self, target: str, port: int, username: str, password: str
    ) -> List[Indicator]:
        """Run comprehensive FTP honeypot detection after successful login.

        Tests advanced FTP commands that honeypots typically don't implement:
        - MLSD (RFC 3659 Machine-readable directory listing)
        - MLST (RFC 3659 Machine-readable file info)
        - EPSV (Extended passive mode for IPv6)
        - EPRT (Extended port command)
        - AUTH TLS (FTP over TLS)
        - SITE commands (CHMOD, etc.)
        - MFMT (Modify time)
        - FEAT analysis (feature count)

        Args:
            target: Target host
            port: FTP port
            username: Username for authentication
            password: Password for authentication

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []
        unsupported_count = 0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read banner
            sock.recv(1024)

            # Login
            sock.send(f"USER {username}\r\n".encode())
            sock.recv(1024)
            sock.send(f"PASS {password}\r\n".encode())
            login_response = sock.recv(1024)

            if b"230" not in login_response:
                sock.close()
                return indicators

            # Helper to send command and get response
            def send_cmd(cmd: str) -> bytes:
                sock.send(f"{cmd}\r\n".encode())
                try:
                    return sock.recv(4096)
                except socket.timeout:
                    return b""

            # Test MLSD - RFC 3659 (Modern FTP) - MEDIUM
            mlsd_response = send_cmd("MLSD")
            if b"502" in mlsd_response or b"500" in mlsd_response:
                unsupported_count += 1
                indicators.append(
                    Indicator(
                        name="ftp_no_mlsd",
                        description="MLSD command not implemented (RFC 3659)",
                        severity=Confidence.MEDIUM,
                        details="Modern FTP servers support MLSD for directory listing",
                    )
                )

            # Test MLST - RFC 3659 - HIGH
            mlst_response = send_cmd("MLST .")
            if b"502" in mlst_response or b"500" in mlst_response:
                unsupported_count += 1

            # Test EPSV - Extended Passive (IPv6) - HIGH
            epsv_response = send_cmd("EPSV")
            if b"502" in epsv_response or b"500" in epsv_response:
                unsupported_count += 1
                indicators.append(
                    Indicator(
                        name="ftp_no_epsv",
                        description="EPSV command not implemented",
                        severity=Confidence.HIGH,
                        details="Extended passive mode required for IPv6 support",
                    )
                )

            # Test EPRT - Extended Port - MEDIUM
            eprt_response = send_cmd("EPRT |1|127.0.0.1|12345|")
            if b"502" in eprt_response or b"500" in eprt_response:
                unsupported_count += 1

            # Test AUTH TLS - FTP over TLS - HIGH
            auth_response = send_cmd("AUTH TLS")
            if b"502" in auth_response or b"500" in auth_response:
                unsupported_count += 1
                indicators.append(
                    Indicator(
                        name="ftp_no_auth_tls",
                        description="AUTH TLS not supported (no secure FTP)",
                        severity=Confidence.HIGH,
                    )
                )

            # Test SITE CHMOD - MEDIUM
            site_response = send_cmd("SITE CHMOD 644 test.txt")
            if b"502" in site_response or b"500" in site_response:
                unsupported_count += 1

            # Test MFMT (Modify file time) - MEDIUM
            mfmt_response = send_cmd("MFMT 20200101120000 test.txt")
            if b"502" in mfmt_response or b"500" in mfmt_response:
                unsupported_count += 1

            # Test FEAT - Feature listing and count - HIGH
            feat_response = send_cmd("FEAT")
            if feat_response:
                if b"211" in feat_response:
                    # Count features (lines between 211- and 211 )
                    feat_lines = feat_response.decode("utf-8", errors="ignore").split("\n")
                    feature_count = sum(1 for line in feat_lines if line.startswith(" "))
                    if feature_count < 3:
                        indicators.append(
                            Indicator(
                                name="ftp_few_features",
                                description=f"FEAT returns only {feature_count} features",
                                severity=Confidence.HIGH,
                                details="Real FTP servers (vsftpd, ProFTPd) have 10+ features",
                            )
                        )
                elif b"500" in feat_response or b"502" in feat_response:
                    unsupported_count += 1
                    indicators.append(
                        Indicator(
                            name="ftp_no_feat",
                            description="FEAT command not supported",
                            severity=Confidence.HIGH,
                        )
                    )

            # Test SYST - System type - MEDIUM
            syst_response = send_cmd("SYST")
            if syst_response:
                syst_str = syst_response.decode("utf-8", errors="ignore")
                # Check for generic/suspicious SYST responses
                if "UNIX" not in syst_str.upper() and "WINDOWS" not in syst_str.upper():
                    indicators.append(
                        Indicator(
                            name="ftp_unusual_syst",
                            description="Unusual SYST response",
                            severity=Confidence.MEDIUM,
                            details=syst_str[:50],
                        )
                    )

            # Test PWD - Should return current directory - MEDIUM
            pwd_response = send_cmd("PWD")
            if pwd_response:
                if b"257" not in pwd_response:
                    indicators.append(
                        Indicator(
                            name="ftp_pwd_failed",
                            description="PWD command failed or not implemented",
                            severity=Confidence.MEDIUM,
                        )
                    )

            # Multiple unsupported modern commands = honeypot
            if unsupported_count >= 4:
                indicators.append(
                    Indicator(
                        name="ftp_limited_implementation",
                        description=f"{unsupported_count} modern FTP commands not implemented",
                        severity=Confidence.DEFINITE,
                        details="Honeypots typically implement only basic FTP commands",
                    )
                )

            # Quit gracefully
            send_cmd("QUIT")
            sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

        return indicators

    def _try_login(self, target: str, port: int, username: str, password: str) -> Tuple[bool, float]:
        """Attempt FTP login and measure timing.

        Returns:
            Tuple of (success, elapsed_time)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read banner
            sock.recv(1024)

            start = time.perf_counter()

            # Send USER
            sock.send(f"USER {username}\r\n".encode())
            user_response = sock.recv(1024)

            # Send PASS
            sock.send(f"PASS {password}\r\n".encode())
            pass_response = sock.recv(1024)

            elapsed = time.perf_counter() - start
            sock.close()

            # Check for successful login (230 = Login successful)
            if b"230" in pass_response:
                return True, elapsed
            return False, elapsed

        except (socket.error, socket.timeout, OSError):
            return False, 0

    def _probe_commands(self, target: str, port: int) -> List[Indicator]:
        """Test FTP command support."""
        indicators = []
        unsupported = 0
        responses = []

        for cmd in FTP_PROBE_COMMANDS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read banner
                sock.recv(1024)

                # Send command
                sock.send(cmd)
                response = sock.recv(1024)
                responses.append(response)

                sock.close()

                # Check for 500/502 (command not implemented)
                if b"500" in response or b"502" in response:
                    unsupported += 1

            except (socket.error, socket.timeout, OSError):
                continue

        # Too many unsupported commands = honeypot
        if unsupported >= 3:
            indicators.append(
                Indicator(
                    name="ftp_limited_commands",
                    description=f"{unsupported}/{len(FTP_PROBE_COMMANDS)} commands not supported",
                    severity=Confidence.MEDIUM,
                    details="Honeypots often implement only basic FTP commands",
                )
            )

        # Check for uniform responses
        if len(responses) >= 3:
            unique = len(set(responses))
            if unique == 1:
                indicators.append(
                    Indicator(
                        name="ftp_uniform_response",
                        description="All commands return identical response",
                        severity=Confidence.HIGH,
                    )
                )

        return indicators

    def _probe_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test FTP response to invalid payloads."""
        indicators = []
        responses = []

        for payload in FTP_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read banner
                sock.recv(1024)

                # Send invalid payload
                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        # Check for uniform error responses
        if len(responses) >= 3:
            unique = set(responses)
            if len(unique) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="ftp_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                        details="Honeypots often return identical errors",
                    )
                )

        return indicators

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for FTP honeypot hardening."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "ftp_honeypot_banner":
                recommendations.append(
                    "Customize FTP banner to match real server software"
                )
            elif indicator.name == "ftp_accept_all":
                recommendations.append(
                    "Implement proper credential validation - don't accept all credentials"
                )
            elif indicator.name == "ftp_limited_commands":
                recommendations.append(
                    "Implement more FTP commands (SYST, FEAT, STAT, HELP)"
                )

        return recommendations
